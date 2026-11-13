(ns mithril.web-scanner.coverage-test
  "Branch coverage - edge cases beyond core/stack/authorization suites."
  (:require [mithril.web-scanner.test-fs :as fs]
            [mithril.web-scanner.test-fs :as fs-host]
            [clojure.edn :as edn]
            [clojure.test :refer [deftest is testing]]
            [mithril.web-scanner.core :as core]
            [mithril.web-scanner.spider :as spider]
            [mithril.web-scanner.passive :as passive]
            [mithril.web-scanner.active :as active]
            [mithril.web-scanner.report :as report]
            [mithril.web-scanner.authorization :as authorization]))

(def ^:private mock-scope
  {:ok true :mode "passive" :max-pages 50
   :assets [{:origin "http://t.local:80" :path "/"}]})

(deftest core-finding-test
  (testing "default severity and omitted optional keys"
    (let [f (core/finding {:rule-id "10038" :title "T" :evidence "E" :url "https://h/"})]
      (is (= :low (:severity f)))
      (is (not (contains? f :param)))
      (is (not (contains? f :cwe)))
      (is (not (contains? f :cve-ids)))
      (is (not (contains? f :cvss)))))
  (testing "keeps optional keys when present"
    (let [f (core/finding {:rule-id "40018" :severity :high :title "T" :evidence "E" :url "https://h/" :param "q" :solution "S" :references ["r"] :cwe "CWE-89" :cve-ids ["CVE-2024-0001"] :cvss 9.8})]
      (is (= "q" (:param f)))
      (is (= "S" (:solution f)))
      (is (= "CWE-89" (:cwe f)))
      (is (= ["CVE-2024-0001"] (:cve-ids f)))
      (is (= 9.8 (:cvss f)))))
  (testing "empty cve-ids omitted"
    (let [f (core/finding {:rule-id "10038" :title "T" :evidence "E" :url "https://h/" :cve-ids []})]
      (is (not (contains? f :cve-ids))))))

(deftest core-target-origin-test
  (testing "http default port"
    (is (= {:scheme "http" :host "example.test" :port "80"} (core/target-origin "http://example.test/p"))))
  (testing "https default port"
    (is (= {:scheme "https" :host "example.test" :port "443"} (core/target-origin "https://example.test/p"))))
  (testing "explicit port"
    (is (= {:scheme "http" :host "example.test" :port "8080"} (core/target-origin "http://example.test:8080/p"))))
  (testing "ipv6"
    (is (= {:scheme "http" :host "[::1]" :port "8080"} (core/target-origin "http://[::1]:8080/p"))))
  (testing "no scheme"
    (is (= {:scheme "http" :host "example.test" :port "80"} (core/target-origin "example.test/p"))))
  (testing "same-origin"
    (is (core/same-origin? "https://example.test/a" "https://example.test/b"))
    (is (not (core/same-origin? "http://example.test/a" "https://example.test/a")))))

(deftest core-normalize-test
  (testing "strip fragment keep query"
    (is (= "https://example.test/a?q=1" (core/normalize-url "https://example.test/a?q=1#frag"))))
  (testing "no fragment"
    (is (= "https://example.test/a" (core/normalize-url "https://example.test/a"))))
  (testing "no scheme"
    (is (= "http://example.test/a" (core/normalize-url "example.test/a#frag")))))

(deftest spider-links-test
  (testing "nil and empty"
    (is (= [] (spider/extract-links nil)))
    (is (= [] (spider/extract-links ""))))
  (testing "mixed quotes case-insensitive"
    (is (= ["/a" "/b" "/c"] (spider/extract-links "<a HREF='/a'>x</a><img src=\"/b\"><form ACTION='/c'>y</form>"))))
  (testing "blank and hash dropped"
    (is (= [] (spider/extract-candidates "https://example.test/" "<a href=''>x</a><a href='#f'>y</a>"))))
  (testing "dedupe and same-origin filter"
    (let [c (spider/extract-candidates "https://example.test/" "<a href='/a'>1</a><a href='/a'>2</a><a href='https://other.test/b'>3</a><a href='/b'>4</a>")]
      (is (= 2 (count c))))))

(deftest spider-budget-test
  (with-redefs [authorization/authorization-scope (fn [_ _ mode _] (assoc mock-scope :mode mode))]
    (testing "invalid budget throws"
      (let [threw? (try (do (spider/spider {:seed-url "http://t.local/" :fetch-fn nil :max-pages 0 :approval-id "x" :mode "passive"}) false)
                       (catch #?(:cljs :default :clj Throwable) _ true))]
        (is threw?)))))

(deftest report-edn-test
  (testing "nil crawl unknown"
    (let [r (report/report-edn {:target "https://h/" :findings [] :started-at "t" :mode "passive" :max-pages 10})]
      (is (= :unknown (:report/collection-state r)))
      (is (nil? (:report/coverage r)))
      (is (= :passive-html-get-v1 (:report/method r)))))
  (testing "active partial and limited method"
    (let [r (report/report-edn {:target "https://h/" :findings [] :started-at "t" :mode "active" :max-pages 10
                                  :crawl {:pages [] :visited #{} :failures [] :queue-drained? true}})]
      (is (= :partial (:report/collection-state r)))
      (is (= :limited-active-get-v1 (:report/method r)))))
  (testing "complete when drained no failures"
    (let [r (report/report-edn {:target "https://h/" :findings [] :started-at "t" :mode "passive" :max-pages 10
                                  :crawl {:pages [{:url "https://h/"}] :visited #{"https://h/"} :failures [] :queue-drained? true}})]
      (is (= :complete (:report/collection-state r)))))
  (testing "partial when failures present"
    (let [r (report/report-edn {:target "https://h/" :findings [] :started-at "t" :mode "passive" :max-pages 10
                                  :crawl {:pages [] :visited #{"https://h/"} :failures [{:url "https://h/"}] :queue-drained? true}})]
      (is (= :partial (:report/collection-state r)))))
  (testing "unknown mode"
    (let [r (report/report-edn {:target "https://h/" :findings [] :started-at "t" :mode "bogus" :max-pages 10})]
      (is (= :unknown (:report/method r))))))

(deftest passive-headers-test
  (testing "all present"
    (let [resp {:status 200 :headers {"Strict-Transport-Security" "max-age=1" "X-Content-Type-Options" "nosniff" "Content-Security-Policy" "x" "X-Frame-Options" "DENY" "Referrer-Policy" "no-referrer" "Permissions-Policy" "camera=()" "Cross-Origin-Opener-Policy" "same-origin" "Cross-Origin-Embedder-Policy" "require-corp" "Cross-Origin-Resource-Policy" "same-origin"} :body ""}]
      (is (empty? (passive/check-security-headers {:url "https://h/"} resp)))))
  (testing "missing eight"
    (let [resp {:status 200 :headers {"X-Content-Type-Options" "nosniff"} :body ""}]
      (is (= 8 (count (passive/check-security-headers {:url "https://h/"} resp)))))))

(deftest passive-cookie-test
  (testing "no cookie"
    (is (empty? (passive/check-cookie-flags {:url "https://h/"} {:status 200 :headers {} :body ""}))))
  (testing "vector cookie"
    (let [resp {:status 200 :headers {"Set-Cookie" ["a=1; Secure; HttpOnly; SameSite=Lax" "b=2"]} :body ""}]
      (is (= 3 (count (passive/check-cookie-flags {:url "https://h/"} resp))))))
  (testing "single cookie no flags"
    (let [resp {:status 200 :headers {"Set-Cookie" "a=1"} :body ""}]
      (is (= 3 (count (passive/check-cookie-flags {:url "https://h/"} resp)))))))

(deftest passive-sensitive-test
  (testing "all four patterns"
    (let [resp {:status 200 :headers {} :body "password=secret123 AKIAIOSFODNN7EXAMPLE -----BEGIN PRIVATE KEY----- jdbc:mysql://h/db"}]
      (is (= 4 (count (passive/check-sensitive-info {:url "https://h/"} resp))))))
  (testing "no leak"
    (is (empty? (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "hello"})))))

(deftest active-params-test
  (testing "no query"
    (is (= [] (active/parse-params "https://example.test/app"))))
  (testing "param without value"
    (is (= [{:name "a" :value "1"} {:name "b" :value ""}] (active/parse-params "https://h/?a=1&b")))))

(deftest active-scan-test
  (with-redefs [authorization/authorization-scope (fn [_ _ mode _] (assoc mock-scope :mode mode))]
    (testing "no params empty"
      (is (= [] (active/active-scan {:url "http://t.local/app" :approval-id "x" :send-fn (fn [_] {:status 200 :headers {} :body ""}) :baseline {:body ""} :max-pages 1}))))
    (testing "baseline suppresses"
      (let [res (active/active-scan {:url "http://t.local/app?id=1" :approval-id "x" :send-fn (fn [_] {:status 200 :headers {} :body "same"}) :baseline {:body "same"} :max-pages 1})]
        (is (empty? res))))
    (testing "probe throws no finding"
      (let [res (active/active-scan {:url "http://t.local/app?id=1" :approval-id "x" :send-fn (fn [_] (throw (ex-info "boom" {}))) :baseline {:body ""} :max-pages 1})]
        (is (empty? res))))))

(deftest passive-cwe-test
  (testing "passive findings carry cwe"
    (let [f (first (passive/check-security-headers {:url "https://h/"} {:status 200 :headers {} :body ""}))]
      (is (= "CWE-693" (:cwe f))))
    (let [f (first (passive/check-cookie-flags {:url "https://h/"} {:status 200 :headers {"Set-Cookie" "a=1"} :body ""}))]
      (is (= "CWE-1004" (:cwe f))))
    (let [f (first (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "password=secret123"}))]
      (is (= "CWE-209" (:cwe f))))))

(deftest report-cwe-json-test
  (testing "finding json includes cwe cve_ids cvss"
    (let [doc (report/report-edn {:target "https://h/" :findings [(core/finding {:rule-id "40018" :title "T" :evidence "E" :url "https://h/" :cwe "CWE-89" :cve-ids ["CVE-2024-0001"] :cvss 9.8})] :started-at "t"}) j (report/report-json doc)]
      (is (re-find #"cwe" j) (str j))
      (is (re-find #"cve_ids" j) (str j))
      (is (re-find #"cvss" j) (str j)))))

(deftest passive-header-disclosure-test
  (testing "server version and x-powered-by"
    (is (= 1 (count (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {"Server" "Apache/2.4.51"} :body ""}))))
    (is (= 1 (count (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {"X-Powered-By" "PHP/8.1"} :body ""}))))
    (is (empty? (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {"Server" "Apache"} :body ""})))))

(deftest active-variants-test
  (testing "payload tables expanded"
    (is (>= (count active/sqli-payloads) 5))
    (is (>= (count active/xss-payloads) 4))
    (is (>= (count active/cmdi-payloads) 5))
    (is (>= (count active/trav-payloads) 5))
    (is (>= (count active/crlf-payloads) 3)))
  (with-redefs [authorization/authorization-scope (fn [_ _ mode _] (assoc mock-scope :mode mode))]
    (testing "encoded traversal probe is sent"
      (let [sent (atom [])
            _ (active/active-scan {:url "http://t.local/app?id=1" :approval-id "x"
                                   :send-fn (fn [r] (swap! sent conj (:url r)) {:status 200 :headers {} :body ""})
                                   :baseline {:body ""} :max-pages 1})]
        (is (some #(re-find #"%252e" %) @sent))))))

(deftest check-cors-test
  (testing "wildcard plus credentials is a finding"
    (let [resp {:status 200 :headers {"Access-Control-Allow-Origin" "*" "Access-Control-Allow-Credentials" "true"} :body ""}]
      (is (= 1 (count (passive/check-cors {:url "https://h/"} resp))))))
  (testing "wildcard without credentials is not a finding"
    (let [resp {:status 200 :headers {"Access-Control-Allow-Origin" "*"} :body ""}]
      (is (empty? (passive/check-cors {:url "https://h/"} resp)))))
  (testing "specific origin is not a finding"
    (let [resp {:status 200 :headers {"Access-Control-Allow-Origin" "https://app.example.com" "Access-Control-Allow-Credentials" "true"} :body ""}]
      (is (empty? (passive/check-cors {:url "https://h/"} resp)))))
  (testing "no cors headers is not a finding"
    (is (empty? (passive/check-cors {:url "https://h/"} {:status 200 :headers {} :body ""})))))

(deftest check-header-variants-test
  (testing "weak values flagged"
    (is (= 1 (count (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Strict-Transport-Security" "max-age=60; includeSubDomains"} :body ""}))))
    (is (= 1 (count (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Strict-Transport-Security" "includeSubDomains"} :body ""}))))
    (is (= 1 (count (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"X-Content-Type-Options" "wrong"} :body ""}))))
    (is (= 1 (count (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Content-Security-Policy" "default-src 'unsafe-inline'"} :body ""}))))
    (is (= 2 (count (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Content-Security-Policy" "default-src *; script-src 'unsafe-eval'"} :body ""}))))
  (testing "strong values not flagged"
    (is (empty? (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Strict-Transport-Security" "max-age=63072000; includeSubDomains"} :body ""})))
    (is (empty? (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"X-Content-Type-Options" "nosniff"} :body ""})))
    (is (empty? (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Content-Security-Policy" "default-src 'self'"} :body ""})))
  (testing "absent headers not flagged here"
    (is (empty? (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {} :body ""})))))))

(deftest check-dir-listing-test
  (testing "markers flagged"
    (is (= 1 (count (passive/check-directory-listing {:url "https://h/"} {:status 200 :headers {} :body "<html><title>Index of /files/</title></html>"}))))
    (is (= 1 (count (passive/check-directory-listing {:url "https://h/"} {:status 200 :headers {} :body "Directory listing for /var/www"}))))
    (is (= 1 (count (passive/check-directory-listing {:url "https://h/"} {:status 200 :headers {} :body "<h1>Apache Directory Listing</h1>"}))))
  (testing "normal body not flagged"
    (is (empty? (passive/check-directory-listing {:url "https://h/"} {:status 200 :headers {} :body "<html>hello</html>"})))))

(deftest check-cookie-prefix-test
  (testing "__Host without Secure flagged"
    (let [resp {:status 200 :headers {"Set-Cookie" "__Host-session=abc; HttpOnly; SameSite=Strict; Path=/"} :body ""}
          n (count (filter #(re-find #"prefix" (str (:title %))) (passive/check-cookie-flags {:url "https://h/"} resp)))]
      (is (= 1 n))))
  (testing "__Host with Domain flagged"
    (let [resp {:status 200 :headers {"Set-Cookie" "__Host-session=abc; Secure; HttpOnly; SameSite=Strict; Path=/; Domain=example.com"} :body ""}
          n (count (filter #(re-find #"prefix" (str (:title %))) (passive/check-cookie-flags {:url "https://h/"} resp)))]
      (is (= 1 n))))
  (testing "__Secure without Secure flagged"
    (let [resp {:status 200 :headers {"Set-Cookie" "__Secure-token=x; HttpOnly; SameSite=Strict; Path=/"} :body ""}
          n (count (filter #(re-find #"prefix" (str (:title %))) (passive/check-cookie-flags {:url "https://h/"} resp)))]
      (is (= 1 n))))
  (testing "compliant __Host not prefix-flagged"
    (let [resp {:status 200 :headers {"Set-Cookie" "__Host-session=abc; Secure; HttpOnly; SameSite=Strict; Path=/"} :body ""}
          n (count (filter #(re-find #"prefix" (str (:title %))) (passive/check-cookie-flags {:url "https://h/"} resp)))]
      (is (zero? n))))))
(deftest spider-js-test
  (testing "js references extracted"
    (is (= "/api/users" (first (spider/extract-js-references "fetch(\"/api/users\")"))))
    (is (some #{"https://h/app.js"} (spider/extract-js-references "var url = \"https://h/app.js\"")))
    (is (some #{"/static/main.js"} (spider/extract-js-references "var x = \"/static/main.js\"")))
    (is (empty? (spider/extract-js-references "var x = 1;"))))
  (testing "candidates include js refs and dedupe"
    (let [cs (spider/extract-candidates "https://h/app" "<script src=\"https://h/api/users\"></script> fetch(\"/api/users\")")]
      (is (some #{"https://h/api/users"} (set cs)))
      (is (= (count cs) (count (set cs)))))))

(deftest check-refresh-test
  (testing "external refresh flagged"
    (is (= 1 (count (passive/check-refresh {:url "https://h/app"} {:status 200 :headers {"Refresh" "5; url=https://evil.example.com/x"} :body ""}))))
    (is (= 1 (count (passive/check-refresh {:url "https://h/app"} {:status 200 :headers {"Refresh" "0; URL=//evil.example.com/x"} :body ""})))))
  (testing "same-origin and delay-only not flagged"
    (is (empty? (passive/check-refresh {:url "https://h/app"} {:status 200 :headers {"Refresh" "5; url=/home"} :body ""})))
    (is (empty? (passive/check-refresh {:url "https://h/app"} {:status 200 :headers {"Refresh" "30"} :body ""})))
    (is (empty? (passive/check-refresh {:url "https://h/app"} {:status 200 :headers {"Refresh" "5; url=https://h/home"} :body ""})))
    (is (empty? (passive/check-refresh {:url "https://h/app"} {:status 200 :headers {} :body ""})))))

(deftest check-cache-privacy-test
  (testing "cacheable session response flagged"
    (is (= 1 (count (passive/check-cache-privacy {:url "https://h/app"} {:status 200 :headers {"Set-Cookie" "sid=abc" "Cache-Control" "public, max-age=60"} :body ""}))))
    (is (= 1 (count (passive/check-cache-privacy {:url "https://h/app"} {:status 200 :headers {"Set-Cookie" "sid=abc" "Cache-Control" "max-age=300"} :body ""})))))
  (testing "protected or non-sensitive not flagged"
    (is (empty? (passive/check-cache-privacy {:url "https://h/app"} {:status 200 :headers {"Set-Cookie" "sid=abc" "Cache-Control" "no-store"} :body ""})))
    (is (empty? (passive/check-cache-privacy {:url "https://h/app"} {:status 200 :headers {"Set-Cookie" "sid=abc" "Cache-Control" "private, max-age=60"} :body ""})))
    (is (empty? (passive/check-cache-privacy {:url "https://h/app"} {:status 200 :headers {"Cache-Control" "public, max-age=60"} :body ""})))
    (is (empty? (passive/check-cache-privacy {:url "https://h/app"} {:status 200 :headers {"Set-Cookie" "sid=abc"} :body ""})))))

(deftest check-location-test
  (testing "external location flagged"
    (is (= 1 (count (passive/check-location-redirect {:url "https://h/app"} {:status 302 :headers {"Location" "https://evil.example.com/x"} :body ""}))))
    (is (= 1 (count (passive/check-location-redirect {:url "https://h/app"} {:status 301 :headers {"Location" "http://other.example.com/"} :body ""})))))
  (testing "same-origin relative absent not flagged"
    (is (empty? (passive/check-location-redirect {:url "https://h/app"} {:status 302 :headers {"Location" "/home"} :body ""})))
    (is (empty? (passive/check-location-redirect {:url "https://h/app"} {:status 302 :headers {"Location" "https://h/home"} :body ""})))
    (is (empty? (passive/check-location-redirect {:url "https://h/app"} {:status 200 :headers {} :body ""})))))

(deftest check-hdr-variant2-test
  (testing "hsts without includeSubDomains flagged"
    (is (= 1 (count (filter #(re-find #"includeSubDomains" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Strict-Transport-Security" "max-age=63072000"} :body ""}))))))
  (testing "hsts with includeSubDomains not subtype-flagged"
    (is (empty? (filter #(re-find #"includeSubDomains" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Strict-Transport-Security" "max-age=63072000; includeSubDomains"} :body ""})))))
  (testing "deprecated x-frame-options flagged"
    (is (= 1 (count (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"X-Frame-Options" "ALLOW-FROM https://a.example.com"} :body ""})))))
  (testing "deny and sameorigin not flagged"
    (is (empty? (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"X-Frame-Options" "DENY"} :body ""})))
    (is (empty? (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"X-Frame-Options" "SAMEORIGIN"} :body ""})))))

(deftest info-header-detail-test
  (testing "via, aspnet, generator headers flagged when versioned"
    (is (= 1 (count (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {"Via" "1.1 squid/3.5.1"} :body ""}))))
    (is (= 1 (count (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {"X-AspNet-Version" "4.0.30319"} :body ""}))))
    (is (= 1 (count (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {"X-Generator" "Drupal 10.2"} :body ""}))))
    (is (= 1 (count (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {"X-AspNetMvc-Version" "5.1"} :body ""})))))
  (testing "versionless values and absent headers not flagged"
    (is (empty? (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {"Via" "proxy"} :body ""})))
    (is (empty? (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {"X-Generator" "Drupal"} :body ""})))
    (is (empty? (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body ""})))))

(deftest check-hdr-variant3-test
  (testing "unknown referrer-policy token flagged"
    (is (= 1 (count (filter #(re-find #"Referrer-Policy value" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Referrer-Policy" "custom-thing"} :body ""}))))))
  (testing "standard referrer-policy tokens not flagged"
    (doseq [v ["no-referrer" "strict-origin" "same-origin" "unsafe-url" "Strict-Origin-When-Cross-Origin"]]
      (is (empty? (filter #(re-find #"Referrer-Policy value" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Referrer-Policy" v} :body ""})))))
  (testing "empty permissions-policy flagged"
    (is (= 1 (count (filter #(re-find #"empty" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Permissions-Policy" ""} :body ""}))))))
  (testing "non-empty permissions-policy not flagged"
    (is (empty? (filter #(re-find #"empty" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Permissions-Policy" "camera=()"} :body ""})))))))

(deftest check-csp-empty-test
  (testing "empty content-security-policy flagged"
    (is (= 1 (count (filter #(re-find #"Content-Security-Policy present but empty" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Content-Security-Policy" ""} :body ""}))))))
  (testing "normal csp not flagged"
    (is (empty? (filter #(re-find #"Content-Security-Policy present but empty" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Content-Security-Policy" "default-src 'self'"} :body ""}))))))

(deftest lfi-trav-variants-test
  (testing "trav payload set grew with encoded/lfi variants"
    (is (>= (count active/trav-payloads) 10))
    (is (some #(clojure.string/includes? (str (:p %)) "file:///") active/trav-payloads))
    (is (some #(clojure.string/includes? (str (:p %)) "%c0%af") active/trav-payloads))))

(deftest sqli-ioc-variants-test
  (testing "sqli payload set grew with db-dialect probes"
    (is (>= (count active/sqli-payloads) 8))
    (is (some #(clojure.string/includes? (str (:p %)) "UNION SELECT") active/sqli-payloads))
    (is (some #(re-find #"PostgreSQL" (str (:re %))) active/sqli-payloads))
    (is (some #(re-find #"SQLite3" (str (:re %))) active/sqli-payloads))))

(deftest cmdi-variant-probes-test
  (testing "cmdi payload set includes IFS/newline/id variants"
    (is (>= (count active/cmdi-payloads) 10))
    (is (some #(clojure.string/includes? (str (:p %)) "IFS") active/cmdi-payloads))
    (is (some #(clojure.string/includes? (str (:p %)) "%0a") active/cmdi-payloads))
    (is (some #(clojure.string/includes? (str (:p %)) "id") active/cmdi-payloads))))

(deftest crlf-variant-probes-test
  (testing "crlf payload set includes encoded/split variants"
    (is (>= (count active/crlf-payloads) 8))
    (is (some #(clojure.string/includes? (str (:p %)) "%250d") active/crlf-payloads))
    (is (some #(clojure.string/includes? (str (:p %)) "%0d%0a%0d%0a") active/crlf-payloads))))

(deftest xss-variant-probes-test
  (testing "xss payload set includes tag-variants"
    (is (>= (count active/xss-payloads) 9))
    (is (some #(re-find #"ontoggle" (str (:p %))) active/xss-payloads))
    (is (some #(re-find #"onfocus" (str (:p %))) active/xss-payloads))
    (is (some #(re-find #"<audio" (str (:p %))) active/xss-payloads))))

(deftest check-cookie-domain-test
  (testing "Domain attribute outside __Host- flagged"
    (is (= 1 (count (filter #(re-find #"(?i)Domain" (str (:title %))) (passive/check-cookie-flags {:url "https://h/"} {:status 200 :headers {"Set-Cookie" "sid=1; Secure; HttpOnly; SameSite=Lax; Domain=.example.com"} :body ""}))))))
  (testing "no Domain attribute not flagged"
    (is (empty? (filter #(re-find #"(?i)Domain" (str (:title %))) (passive/check-cookie-flags {:url "https://h/"} {:status 200 :headers {"Set-Cookie" "sid=1; Secure; HttpOnly; SameSite=Lax; Path=/"} :body ""})))))
  (testing "__Host cookie with Domain only counts once"
    (is (= 1 (count (filter #(re-find #"__Host-/__Secure- prefix" (str (:title %))) (passive/check-cookie-flags {:url "https://h/"} {:status 200 :headers {"Set-Cookie" "__Host-sid=1; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=.example.com"} :body ""})))))))

(deftest check-cors-reflection-test
  (testing "reflected origin with credentials flagged"
    (is (= 1 (count (filter #(re-find #"(?i)reflection" (str (:title %))) (passive/check-cors {:url "https://h/" :headers {"Origin" "https://evil.example"}} {:status 200 :headers {"Access-Control-Allow-Origin" "https://evil.example" "Access-Control-Allow-Credentials" "true"} :body ""}))))))
  (testing "trusted fixed origin with credentials not flagged for reflection"
    (is (empty? (filter #(re-find #"(?i)reflection" (str (:title %))) (passive/check-cors {:url "https://h/" :headers {"Origin" "https://evil.example"}} {:status 200 :headers {"Access-Control-Allow-Origin" "https://api.example.com" "Access-Control-Allow-Credentials" "true"} :body ""})))))
  (testing "reflected origin without credentials not flagged for reflection"
    (is (empty? (filter #(re-find #"(?i)reflection" (str (:title %))) (passive/check-cors {:url "https://h/" :headers {"Origin" "https://evil.example"}} {:status 200 :headers {"Access-Control-Allow-Origin" "https://evil.example"} :body ""})))))
  (testing "no request Origin header: reflection branch skipped"
    (is (empty? (passive/check-cors {:url "https://h/"} {:status 200 :headers {"Access-Control-Allow-Origin" "https://evil.example" "Access-Control-Allow-Credentials" "true"} :body ""})) )))

(deftest check-isolation-headers-test
  (testing "non-standard coop value flagged"
    (is (= 1 (count (filter #(re-find #"(?i)Opener-Policy value" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Cross-Origin-Opener-Policy" "custom"} :body ""}))))))
  (testing "non-standard coep value flagged"
    (is (= 1 (count (filter #(re-find #"(?i)Embedder-Policy value" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Cross-Origin-Embedder-Policy" "custom"} :body ""}))))))
  (testing "non-standard corp value flagged"
    (is (= 1 (count (filter #(re-find #"(?i)Resource-Policy value" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Cross-Origin-Resource-Policy" "custom"} :body ""}))))))
  (testing "standard isolation values not flagged"
    (is (empty? (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Cross-Origin-Opener-Policy" "same-origin" "Cross-Origin-Embedder-Policy" "require-corp" "Cross-Origin-Resource-Policy" "same-origin"} :body ""})))))

(deftest xss-cmdi-variant2-test
  (testing "xss has js-uri variants; cmdi has cmd.exe variant"
    (is (>= (count active/xss-payloads) 11))
    (is (some #(clojure.string/includes? (str (:p %)) "javascript:") active/xss-payloads))
    (is (>= (count active/cmdi-payloads) 11))
    (is (some #(clojure.string/includes? (str (:p %)) "& echo") active/cmdi-payloads))))

(deftest check-sensitive-extra-test
  (testing "private key material flagged"
    (is (= 1 (count (filter #(re-find #"(?i)private key material" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "-----BEGIN RSA PRIVATE KEY-----rest"}))))))
  (testing "AWS access key id flagged"
    (is (= 1 (count (filter #(re-find #"(?i)AWS access key id" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "key AKIAIOSFODNN7EXAMPLE end"}))))))
  (testing "database URL with credentials flagged"
    (is (= 1 (count (filter #(re-find #"(?i)database connection string" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "mongodb://user:pass@db:27017/app"}))))))
  (testing "certificate block flagged"
    (is (= 1 (count (filter #(re-find #"(?i)certificate material" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "-----BEGIN CERTIFICATE-----rest"}))))))
  (testing "benign body not flagged"
    (is (empty? (filter #(re-find #"(?i)private key material|AWS access key id|database connection string|certificate material" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "welcome to the site"}))))))
  (testing "HTTP URL without credentials not flagged as database string"
    (is (empty? (filter #(re-find #"(?i)database connection string" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "postgres://db.example.com/app"})))))

(deftest sqli-comment-variants-test
  (testing "sqli payload set includes comment-obfuscated variants"
    (is (>= (count active/sqli-payloads) 12))
    (is (some #(clojure.string/includes? (str (:p %)) "OR/**/") active/sqli-payloads))
    (is (some #(clojure.string/includes? (str (:p %)) "%27%20OR") active/sqli-payloads))
    (is (some #(clojure.string/includes? (str (:p %)) "UNION SELECT") active/sqli-payloads))))

(deftest trav2-variants-test
  (testing "trav payload set includes mixed-encoded + windows + shadow variants"
    (is (>= (count active/trav-payloads) 14))
    (is (some #(clojure.string/includes? (str (:p %)) "%2e%2e%2f") active/trav-payloads))
    (is (some #(clojure.string/includes? (str (:p %)) "win.ini") active/trav-payloads))
    (is (some #(clojure.string/includes? (str (:p %)) "/etc/shadow") active/trav-payloads))))

(deftest check-expires-cache-test
  (testing "Set-Cookie with future Expires flagged"
    (is (= 1 (count (filter #(re-find #"(?i)may be cached" (str (:title %))) (passive/check-cache-privacy {:url "https://h/"} {:status 200 :headers {"Set-Cookie" "sid=1; Secure; HttpOnly; SameSite=Lax" "Expires" "Fri, 01 Jan 2038 00:00:00 GMT"} :body ""}))))))
  (testing "Set-Cookie with past Expires not flagged via Expires"
    (is (empty? (passive/check-cache-privacy {:url "https://h/"} {:status 200 :headers {"Set-Cookie" "sid=1; Secure; HttpOnly; SameSite=Lax" "Expires" "Thu, 01 Jan 1970 00:00:00 GMT"} :body ""}))))
  (testing "Expires future but no-store protected"
    (is (empty? (passive/check-cache-privacy {:url "https://h/"} {:status 200 :headers {"Set-Cookie" "sid=1; Secure; HttpOnly; SameSite=Lax" "Expires" "Fri, 01 Jan 2038 00:00:00 GMT" "Cache-Control" "no-store"} :body ""})))))

(deftest check-dirlist-extra-test
  (testing "tomcat h1 and iis objects in folder detected"
    (is (= 1 (count (passive/check-directory-listing {:url "https://h/"} {:status 200 :headers {} :body "<h1>Directory Listing</h1>"}))))
    (is (= 1 (count (passive/check-directory-listing {:url "https://h/"} {:status 200 :headers {} :body "Objects in Folder /files"}))))
    (is (= 1 (count (passive/check-directory-listing {:url "https://h/"} {:status 200 :headers {} :body "<title>Directory Listing</title>"}))))) 
  (testing "plain page not flagged"
    (is (empty? (passive/check-directory-listing {:url "https://h/"} {:status 200 :headers {} :body "hello"})))))

(deftest check-cookie-samesite-values-test
  (testing "SameSite=None without Secure flagged, with Secure not flagged"
    (is (= 1 (count (filter #(re-find #"(?i)SameSite=None without Secure" (str (:title %))) (passive/check-cookie-flags {:url "https://h/"} {:status 200 :headers {"Set-Cookie" "sid=1; HttpOnly; SameSite=None"} :body ""}))))))
    (is (empty? (filter #(re-find #"(?i)SameSite=None without Secure" (str (:title %))) (passive/check-cookie-flags {:url "https://h/"} {:status 200 :headers {"Set-Cookie" "sid=1; Secure; HttpOnly; SameSite=None"} :body ""})))))
  (testing "invalid SameSite value flagged; Lax accepted"
    (is (= 1 (count (filter #(re-find #"(?i)invalid SameSite value" (str (:title %))) (passive/check-cookie-flags {:url "https://h/"} {:status 200 :headers {"Set-Cookie" "sid=1; Secure; HttpOnly; SameSite=False"} :body ""}))))))
    (is (empty? (filter #(re-find #"(?i)invalid SameSite value" (str (:title %))) (passive/check-cookie-flags {:url "https://h/"} {:status 200 :headers {"Set-Cookie" "sid=1; Secure; HttpOnly; SameSite=Lax"} :body ""}))))

(deftest crlf2-variants-test
  (testing "crlf payload set includes uppercase + Set-Cookie variants"
    (is (>= (count active/crlf-payloads) 11))
    (is (some #(clojure.string/includes? (str (:p %)) "%0D%0A") active/crlf-payloads))
    (is (some #(clojure.string/includes? (str (:p %)) "Set-Cookie") active/crlf-payloads))
    (is (some #(clojure.string/includes? (str (:p %)) "%0A") active/crlf-payloads))))

(deftest check-location-scheme-test
  (testing "javascript: Location flagged high; https external stays low; same-origin clean"
    (is (= 1 (count (filter #(re-find #"(?i)dangerous javascript" (str (:title %))) (passive/check-location-redirect {:url "https://h/"} {:status 302 :headers {"Location" "javascript:alert(1)"} :body ""}))))))
    (is (= 1 (count (filter #(re-find #"(?i)external origin" (str (:title %))) (passive/check-location-redirect {:url "https://h/"} {:status 302 :headers {"Location" "https://evil.test/x"} :body ""}))))))
    (is (empty? (passive/check-location-redirect {:url "https://h/"} {:status 302 :headers {"Location" "https://h/x"} :body ""})))

(deftest check-pp-wild-test
  (testing "wildcard Permissions-Policy flagged; empty stays empty-flag; enumerated clean"
    (is (= 1 (count (filter #(re-find #"(?i)wildcard feature access" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Permissions-Policy" "camera=*"} :body ""}))))))
    (is (= 1 (count (filter #(re-find #"(?i)present but empty" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Permissions-Policy" ""} :body ""}))))))
    (is (empty? (filter #(re-find #"(?i)wildcard feature access" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Permissions-Policy" "camera=(self)"} :body ""}))))

(deftest check-refresh-scheme-test
  (testing "javascript: Refresh flagged high; https external stays low; same-origin and delay-only clean"
    (is (= 1 (count (filter #(re-find #"(?i)dangerous javascript" (str (:title %))) (passive/check-refresh {:url "https://h/"} {:status 302 :headers {"Refresh" "0; url=javascript:alert(1)"} :body ""}))))))
    (is (= 1 (count (filter #(re-find #"(?i)external origin" (str (:title %))) (passive/check-refresh {:url "https://h/"} {:status 302 :headers {"Refresh" "0; url=https://evil.test/x"} :body ""})))))
    (is (empty? (passive/check-refresh {:url "https://h/"} {:status 302 :headers {"Refresh" "0; url=https://h/x"} :body ""})))
    (is (empty? (passive/check-refresh {:url "https://h/"} {:status 302 :headers {"Refresh" "30"} :body ""}))))

(deftest check-cors-acah-wild-test
  (testing "ACAH wildcard with credentials flagged; without cred clean; enumerated clean"
    (is (= 1 (count (filter #(re-find #"(?i)Allow-Headers wildcard" (str (:title %))) (passive/check-cors {:url "https://h/"} {:status 200 :headers {"Access-Control-Allow-Headers" "*" "Access-Control-Allow-Credentials" "true"} :body ""}))))))
    (is (empty? (filter #(re-find #"(?i)Allow-Headers wildcard" (str (:title %))) (passive/check-cors {:url "https://h/"} {:status 200 :headers {"Access-Control-Allow-Headers" "*"} :body ""}))))
    (is (empty? (filter #(re-find #"(?i)Allow-Headers wildcard" (str (:title %))) (passive/check-cors {:url "https://h/"} {:status 200 :headers {"Access-Control-Allow-Headers" "X-Token" "Access-Control-Allow-Credentials" "true"} :body ""})))))

(deftest check-sensitive-cred-url-test
  (testing "ftp/smtps URL with credentials flagged; bare host not flagged"
    (is (= 1 (count (filter #(re-find #"(?i)URL with embedded credentials" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "ftp://user:pass@files.example.com/x"}))))))
    (is (= 1 (count (filter #(re-find #"(?i)URL with embedded credentials" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "smtps://svc:secret@mail.example.com"}))))))
    (is (empty? (filter #(re-find #"(?i)URL with embedded credentials" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "ftp://files.example.com/x"}))))

(deftest check-apache-version-test
  (testing "Apache version in body flagged; generic text clean"
    (is (= 1 (count (filter #(re-find #"(?i)Apache version disclosure" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Apache/2.4.49 (Ubuntu)"}))))))
    (is (empty? (filter #(re-find #"(?i)Apache version disclosure" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the Apache web server"})))))

(deftest check-iis-version-test
  (testing "IIS version in body flagged; generic text clean"
    (is (= 1 (count (filter #(re-find #"(?i)IIS version disclosure" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Microsoft-IIS/8.5"}))))))
    (is (empty? (filter #(re-find #"(?i)IIS version disclosure" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the Microsoft IIS server"})))))

(deftest check-csp-wild-test
  (testing "wildcard default/script source flagged; specific origin clean"
    (is (= 1 (count (filter #(re-find #"(?i)wildcard default/script source" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Content-Security-Policy" "default-src *"} :body ""}))))))
    (is (empty? (filter #(re-find #"(?i)wildcard default/script source" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Content-Security-Policy" "script-src https://cdn.example.com 'self'"} :body ""}))))
    (is (empty? (filter #(re-find #"(?i)wildcard default/script source" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Content-Security-Policy" "default-src 'self'; script-src 'self'"} :body ""})))))

(deftest check-nginx-version-test
  (testing "nginx version in body flagged; generic text clean"
    (is (= 1 (count (filter #(re-find #"(?i)nginx version disclosure" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "nginx/1.18.0 (Ubuntu)"}))))))
    (is (empty? (filter #(re-find #"(?i)nginx version disclosure" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the nginx web server"})))))

(deftest check-www-authenticate-test
  (testing "WWW-Authenticate over http flagged; https and no-header clean"
    (is (= 1 (count (filter #(re-find #"(?i)plaintext HTTP" (str (:title %))) (passive/check-www-authenticate {:url "http://h/login"} {:status 401 :headers {"WWW-Authenticate" "Basic realm=\"admin\""} :body ""}))))))
    (is (empty? (passive/check-www-authenticate {:url "https://h/login"} {:status 401 :headers {"WWW-Authenticate" "Basic realm=\"admin\""} :body ""}))))
    (is (empty? (passive/check-www-authenticate {:url "http://h/"} {:status 200 :headers {} :body ""})))

(deftest check-rp-unsafe-test
  (testing "unsafe-url flagged; standard tokens and absent clean"
    (is (= 1 (count (filter #(re-find #"(?i)unsafe-url" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Referrer-Policy" "unsafe-url"} :body ""}))))))
    (is (empty? (filter #(re-find #"(?i)unsafe-url" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Referrer-Policy" "strict-origin"} :body ""}))))
    (is (empty? (filter #(re-find #"(?i)unsafe-url" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {} :body ""})))))

(deftest xss-smil-variant-test
  (testing "XSS SMIL animate payload present"
    (is (>= (count active/xss-payloads) 12))
    (is (some #(re-find #"(?i)onbegin" (str (:p %))) active/xss-payloads))))

(deftest xss-mathml-variant-test
  (testing "XSS MathML mtext payload present"
    (is (>= (count active/xss-payloads) 13))
    (is (some #(re-find #"(?i)<math" (str (:p %))) active/xss-payloads))))

(deftest sqli-unionall-variant-test
  (testing "SQLi UNION ALL payload present"
    (is (>= (count active/sqli-payloads) 13))
    (is (some #(re-find #"(?i)UNION ALL" (str (:p %))) active/sqli-payloads))))

(deftest trav-doubleenc-variant-test
  (testing "Traversal double-encoded payload present"
    (is (>= (count active/trav-payloads) 15))
    (is (some #(clojure.string/includes? (str (:p %)) "%252e%252e%252f") active/trav-payloads))))

(deftest crlf-hoax-variant-test
  (testing "CRLF hoax header payload present"
    (is (>= (count active/crlf-payloads) 12))
    (is (some #(re-find #"(?i)hoax=42" (str (:re %))) active/crlf-payloads))))

(deftest check-cors-acam-wild-test
  (testing "Allow-Methods * with credentials flagged; without clean"
    (is (= 1 (count (filter #(re-find #"(?i)Allow-Methods wildcard" (str (:title %))) (passive/check-cors {:url "https://h/" :headers {}} {:status 200 :headers {"Access-Control-Allow-Origin" "https://app.example.com" "Access-Control-Allow-Credentials" "true" "Access-Control-Allow-Methods" "*"} :body ""}))))))
    (is (empty? (filter #(re-find #"(?i)Allow-Methods wildcard" (str (:title %))) (passive/check-cors {:url "https://h/" :headers {}} {:status 200 :headers {"Access-Control-Allow-Origin" "https://app.example.com" "Access-Control-Allow-Credentials" "true" "Access-Control-Allow-Methods" "GET, POST"} :body ""})))))

(deftest check-cache-pragma-only-test
  (testing "Set-Cookie with Pragma-only no-cache flagged; Cache-Control present clean"
    (is (= 1 (count (filter #(re-find #"(?i)Pragma-only" (str (:title %))) (passive/check-cache-privacy {:url "https://h/"} {:status 200 :headers {"Set-Cookie" "sid=1" "Pragma" "no-cache"} :body ""}))))))
    (is (empty? (filter #(re-find #"(?i)Pragma-only" (str (:title %))) (passive/check-cache-privacy {:url "https://h/"} {:status 200 :headers {"Set-Cookie" "sid=1" "Pragma" "no-cache" "Cache-Control" "no-store"} :body ""}))))
    (is (empty? (filter #(re-find #"(?i)Pragma-only" (str (:title %))) (passive/check-cache-privacy {:url "https://h/"} {:status 200 :headers {"Set-Cookie" "sid=1"} :body ""})))))

(deftest check-corp-unsafe-test
  (testing "CORP cross-origin flagged; same-origin and absent clean"
    (is (= 1 (count (filter #(re-find #"(?i)cross-origin permits" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Cross-Origin-Resource-Policy" "cross-origin"} :body ""}))))))
    (is (empty? (filter #(re-find #"(?i)cross-origin permits" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"Cross-Origin-Resource-Policy" "same-origin"} :body ""}))))
    (is (empty? (filter #(re-find #"(?i)cross-origin permits" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {} :body ""})))))

(deftest xss-basetag-variant-test
  (testing "XSS base-tag payload present"
    (is (>= (count active/xss-payloads) 14))
    (is (some #(re-find #"(?i)<base" (str (:p %))) active/xss-payloads))))

(deftest ssti-family-test
  (testing "SSTI family present with marker payloads"
    (is (> (count active/rule-families) 5))
    (let [f (first (filter #(= "40021" (:rule-id %)) active/rule-families))]
      (is (= "CWE-94" (:cwe f)))
      (is (>= (count (:payloads f)) 4))
      (is (some #(re-find #"\{\{7\*7\}\}" (str (:p %))) (:payloads f))))))

(deftest check-server-version-test
  (testing "Server header with version flagged; plain Server and absent clean"
    (is (= 1 (count (filter #(re-find #"(?i)Server header exposes" (str (:title %))) (passive/check-server-version {:url "https://h/"} {:status 200 :headers {"Server" "nginx/1.18.0 (Ubuntu)"} :body ""}))))))
    (is (empty? (passive/check-server-version {:url "https://h/"} {:status 200 :headers {"Server" "nginx"} :body ""}))))
    (is (empty? (passive/check-server-version {:url "https://h/"} {:status 200 :headers {} :body ""})))

(deftest check-xxss-auditor-test
  (testing "X-XSS-Protection mode=allow flagged; 0 and absent clean"
    (is (= 1 (count (filter #(re-find #"(?i)XSS auditor" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"X-XSS-Protection" "1; mode=allow"} :body ""}))))))
    (is (empty? (filter #(re-find #"(?i)XSS auditor" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"X-XSS-Protection" "0"} :body ""}))))
    (is (empty? (filter #(re-find #"(?i)XSS auditor" (str (:title %))) (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {} :body ""})))))

(deftest check-cookie-host-path-test
  (testing "__Host- without Path=/ flagged; with Path=/ clean"
    (is (= 1 (count (filter #(re-find #"(?i)__Host" (str (:title %))) (passive/check-cookie-flags {:url "https://h/"} {:status 200 :headers {"Set-Cookie" "__Host-sid=1; Secure; SameSite=Lax"} :body ""}))))))
    (is (empty? (filter #(re-find #"(?i)__Host" (str (:title %))) (passive/check-cookie-flags {:url "https://h/"} {:status 200 :headers {"Set-Cookie" "__Host-sid=1; Secure; Path=/; SameSite=Lax"} :body ""})))))

(deftest check-powered-by-test
  (testing "X-Powered-By with version flagged; plain and absent clean"
    (is (= 1 (count (filter #(re-find #"(?i)X-Powered-By header exposes" (str (:title %))) (passive/check-server-version {:url "https://h/"} {:status 200 :headers {"X-Powered-By" "PHP/7.4.3"} :body ""}))))))
    (is (empty? (filter #(re-find #"(?i)X-Powered-By header exposes" (str (:title %))) (passive/check-server-version {:url "https://h/"} {:status 200 :headers {"X-Powered-By" "PHP"} :body ""})))))

(deftest xxe-family-test
  (testing "XXE family present with payloads"
    (let [f (first (filter #(= "40020" (:rule-id %)) active/rule-families))]
      (is (= "CWE-611" (:cwe f)))
      (is (>= (count (:payloads f)) 3))
      (is (some #(re-find #"(?i)SYSTEM" (str (:p %))) (:payloads f))))))

(deftest ldap-family-test
  (testing "LDAP family present with payloads"
    (let [f (first (filter #(= "40022" (:rule-id %)) active/rule-families))]
      (is (= "CWE-90" (:cwe f)))
      (is (>= (count (:payloads f)) 3))
      (is (some #(re-find #"\*\)" (str (:p %))) (:payloads f))))))

(deftest nosqli-family-test
  (testing "NoSQL family present with operator payloads"
    (let [f (first (filter #(= "40023" (:rule-id %)) active/rule-families))]
      (is (= "CWE-943" (:cwe f)))
      (is (>= (count (:payloads f)) 3))
      (is (some #(re-find #"\$ne" (str (:p %))) (:payloads f))))))

(deftest el-family-test
  (testing "EL family present with payloads"
    (let [f (first (filter #(= "40024" (:rule-id %)) active/rule-families))]
      (is (= "CWE-917" (:cwe f)))
      (is (>= (count (:payloads f)) 3))
      (is (some #(re-find #"\$\{7\*7\}" (str (:p %))) (:payloads f))))))

(deftest check-caddy-version-test
  (testing "Caddy version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)caddy version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via caddy/2.7.4"})))))
    (is (empty? (filter #(re-find #"(?i)caddy version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the caddy web server"}))))))

(deftest check-litespeed-version-test
  (testing "LiteSpeed version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)litespeed version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Served by LiteSpeed/6.1.2"})))))
    (is (empty? (filter #(re-find #"(?i)litespeed version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the litespeed web server"}))))))

(deftest check-cors-null-test
  (testing "CORS null origin with credentials flagged; without credentials clean"
    (is (= 1 (count (filter #(re-find #"(?i)null origin" (str (:title %))) (passive/check-cors {:url "https://h/" :headers {}} {:status 200 :headers {"Access-Control-Allow-Origin" "null" "Access-Control-Allow-Credentials" "true"} :body ""}))))))
    (is (empty? (filter #(re-find #"(?i)null origin" (str (:title %))) (passive/check-cors {:url "https://h/" :headers {}} {:status 200 :headers {"Access-Control-Allow-Origin" "null"} :body ""})))))

(deftest check-tengine-version-test
  (testing "Tengine version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)tengine version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via tengine/2.3.2"})))))
    (is (empty? (filter #(re-find #"(?i)tengine version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the tengine web server"}))))))

(deftest check-openresty-version-test
  (testing "OpenResty version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)openresty version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via openresty/1.21.4"})))))
    (is (empty? (filter #(re-find #"(?i)openresty version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the openresty web server"}))))))

(deftest check-tomcat-version-test
  (testing "Apache Tomcat version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)apache tomcat version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Apache Tomcat/9.0.98"})))))
    (is (empty? (filter #(re-find #"(?i)apache tomcat version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the apache tomcat web server"}))))))

(deftest check-nodejs-version-test
  (testing "Node.js version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)node\.js version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Node.js/v20.11.1"})))))
    (is (empty? (filter #(re-find #"(?i)node\.js version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the node.js web server"}))))))

(deftest check-werkzeug-version-test
  (testing "Werkzeug version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)werkzeug version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Werkzeug/3.0.3"})))))
    (is (empty? (filter #(re-find #"(?i)werkzeug version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the werkzeug web server"}))))))

(deftest check-curl-version-test
  (testing "curl version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)curl version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via curl/8.5.0"})))))
    (is (empty? (filter #(re-find #"(?i)curl version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the curl tool"}))))))

(deftest check-wget-version-test
  (testing "wget version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)wget version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via wget/1.21.3"})))))
    (is (empty? (filter #(re-find #"(?i)wget version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the wget tool"}))))))

(deftest check-boa-version-test
  (testing "Boa version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)boa version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Boa/0.94.14"})))))
    (is (empty? (filter #(re-find #"(?i)boa version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the boa web server"}))))))

(deftest check-webmin-version-test
  (testing "Webmin version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)webmin version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Webmin/1.941"})))))
    (is (empty? (filter #(re-find #"(?i)webmin version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the webmin admin console"}))))))

(deftest check-varnish-version-test
  (testing "Varnish version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)varnish version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Varnish/7.5.0"})))))
    (is (empty? (filter #(re-find #"(?i)varnish version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the varnish cache server"}))))))

(deftest check-squid-version-test
  (testing "Squid version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)squid version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via squid/5.9"})))))
    (is (empty? (filter #(re-find #"(?i)squid version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the squid proxy server"}))))))

(deftest check-hikari-version-test
  (testing "Hikari version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)hikari version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Hikari/4.0.3"})))))
    (is (empty? (filter #(re-find #"(?i)hikari version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the hikari connection pool"}))))))

(deftest check-jetty-version-test
  (testing "Jetty version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)jetty version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Jetty/11.0.15"})))))
    (is (empty? (filter #(re-find #"(?i)jetty version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the jetty web server"}))))))

(deftest check-gretty-version-test
  (testing "Gretty version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)gretty version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Gretty/3.4.0"})))))
    (is (empty? (filter #(re-find #"(?i)gretty version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the gretty web server"}))))))

(deftest check-tcat-version-test
  (testing "Tcat version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)tcat version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Tcat/1.5.0"})))))
    (is (empty? (filter #(re-find #"(?i)tcat version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the tcat web server"}))))))

(deftest check-jboss-version-test
  (testing "JBoss version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)jboss version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via JBoss/7.4.0"})))))
    (is (empty? (filter #(re-find #"(?i)jboss version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the jboss application server"}))))))

(deftest check-weblogic-version-test
  (testing "WebLogic version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)weblogic version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via WebLogic/14.1.1"})))))
    (is (empty? (filter #(re-find #"(?i)weblogic version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the weblogic application server"}))))))

(deftest check-resin-version-test
  (testing "Resin version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)resin version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Resin/4.0.51"})))))
    (is (empty? (filter #(re-find #"(?i)resin version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the resin web server"}))))))

(deftest check-payara-version-test
  (testing "Payara version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)payara version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Payara/5.2021.10"})))))
    (is (empty? (filter #(re-find #"(?i)payara version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the payara application server"}))))))

(deftest check-wildfly-version-test
  (testing "WildFly version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)wildfly version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via WildFly/27.0.1"})))))
    (is (empty? (filter #(re-find #"(?i)wildfly version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the wildfly application server"}))))))

(deftest check-glassfish-version-test
  (testing "GlassFish version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)glassfish version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via GlassFish/5.1.0"})))))
    (is (empty? (filter #(re-find #"(?i)glassfish version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the glassfish application server"}))))))

(deftest check-grizzly-version-test
  (testing "Grizzly version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)grizzly version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Grizzly/4.1.0"})))))
    (is (empty? (filter #(re-find #"(?i)grizzly version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the grizzly web framework"}))))))

(deftest check-header-values-test
  (testing "X-Content-Type-Options / X-Frame-Options weak values flagged; clean values pass"
    (is (not (empty? (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"X-Content-Type-Options" "SNORF"} :body ""}))))
    (is (empty? (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"X-Content-Type-Options" "nosniff"} :body ""})))
    (is (not (empty? (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"X-Frame-Options" "ALLOW-FROM https://x/"} :body ""}))))
    (is (empty? (passive/check-header-variants {:url "https://h/"} {:status 200 :headers {"X-Frame-Options" "DENY"} :body ""})))))

(deftest check-mojolicious-version-test
  (testing "Mojolicious version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)mojolicious version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Mojolicious/9.39"})))))
    (is (empty? (filter #(re-find #"(?i)mojolicious version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the mojolicious web framework"}))))))

(deftest check-starlette-version-test
  (testing "Starlette version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)starlette version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Starlette/0.36.3"})))))
    (is (empty? (filter #(re-find #"(?i)starlette version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the starlette web framework"}))))))

(deftest check-tornado-version-test
  (testing "Tornado version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)tornado version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Tornado/6.4.0"})))))
    (is (empty? (filter #(re-find #"(?i)tornado version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the tornado web framework"}))))))

(deftest check-sanic-version-test
  (testing "Sanic version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)sanic version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Sanic/23.12.0"})))))
    (is (empty? (filter #(re-find #"(?i)sanic version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the sanic web framework"}))))))

(deftest check-quart-version-test
  (testing "Quart version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)quart version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Quart/0.19.4"})))))
    (is (empty? (filter #(re-find #"(?i)quart version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the quart web framework"}))))))

(deftest check-falcon-version-test
  (testing "Falcon version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)falcon version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Falcon/3.1.3"})))))
    (is (empty? (filter #(re-find #"(?i)falcon version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the falcon web framework"}))))))

(deftest check-elysia-version-test
  (testing "Elysia version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)elysia version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Elysia/1.2.0"})))))
    (is (empty? (filter #(re-find #"(?i)elysia version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the elysia web framework"}))))))

(deftest check-hono-version-test
  (testing "Hono version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)hono version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Hono/4.6.5"})))))
    (is (empty? (filter #(re-find #"(?i)hono version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the hono web framework"}))))))

(deftest check-fiber-version-test
  (testing "Fiber version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)fiber version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Fiber/2.52.5"})))))
    (is (empty? (filter #(re-find #"(?i)fiber version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the fiber web framework"}))))))

(deftest check-gin-version-test
  (testing "Gin version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)gin version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Gin/1.9.1"})))))
    (is (empty? (filter #(re-find #"(?i)gin version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the gin web framework"}))))))

(deftest check-echo-version-test
  (testing "Echo version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)echo version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Echo/4.11.4"})))))
    (is (empty? (filter #(re-find #"(?i)echo version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the echo web framework"}))))))

(deftest check-chi-version-test
  (testing "Chi version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)chi version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Chi/5.0.12"})))))
    (is (empty? (filter #(re-find #"(?i)chi version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the chi web router"}))))))

(deftest check-mux-version-test
  (testing "Mux version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)mux version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Mux/1.8.1"})))))
    (is (empty? (filter #(re-find #"(?i)mux version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the mux router"}))))))

(deftest check-gorilla-version-test
  (testing "Gorilla version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)gorilla version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Gorilla/1.8.0"})))))
    (is (empty? (filter #(re-find #"(?i)gorilla version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the gorilla web toolkit"}))))))

(deftest check-httprouter-version-test
  (testing "httprouter version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)httprouter version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via httprouter/1.3.0"})))))
    (is (empty? (filter #(re-find #"(?i)httprouter version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the httprouter router"}))))))

(deftest check-plack-version-test
  (testing "Plack version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)plack version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Plack/1.0051"})))))
    (is (empty? (filter #(re-find #"(?i)plack version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the plack web toolkit"}))))))

(deftest check-dancer-version-test
  (testing "Dancer version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)dancer version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Dancer/0.303"})))))
    (is (empty? (filter #(re-find #"(?i)dancer version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the dancer web framework"}))))))

(deftest check-catalyst-version-test
  (testing "Catalyst version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)catalyst version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Catalyst/5.90128"})))))
    (is (empty? (filter #(re-find #"(?i)catalyst version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the catalyst web framework"}))))))

(deftest check-starman-version-test
  (testing "Starman version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)starman version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Starman/0.4010"})))))
    (is (empty? (filter #(re-find #"(?i)starman version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the starman web server"}))))))

(deftest check-carton-version-test
  (testing "Carton version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)carton version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Carton/1.0.35"})))))
    (is (empty? (filter #(re-find #"(?i)carton version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the carton dependency manager"}))))))

(deftest check-lwp-version-test
  (testing "LWP version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)lwp version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via LWP/6.68"})))))
    (is (empty? (filter #(re-find #"(?i)lwp version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the lwp user agent"}))))))

(deftest check-dbix-version-test
  (testing "DBIx version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)dbix version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via DBIx/0.89"})))))
    (is (empty? (filter #(re-find #"(?i)dbix version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the dbix toolkit"}))))))

(deftest check-moose-version-test
  (testing "Moose version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)moose version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Moose/2.14"})))))
    (is (empty? (filter #(re-find #"(?i)moose version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the moose object system"}))))))

(deftest check-datetime-version-test
  (testing "DateTime version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)datetime version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via DateTime/1.66"})))))
    (is (empty? (filter #(re-find #"(?i)datetime version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the datetime module"}))))))

(deftest check-jsonpp-version-test
  (testing "JSON::PP version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)json::pp version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via JSON::PP/4.16"})))))
    (is (empty? (filter #(re-find #"(?i)json::pp version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the json::pp module"}))))))

(deftest check-encode-version-test
  (testing "Encode version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)encode version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Encode/3.19"})))))
    (is (empty? (filter #(re-find #"(?i)encode version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the encode module"}))))))

(deftest check-perl-version-test
  (testing "Perl version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)perl version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Perl/5.40.1"})))))
    (is (empty? (filter #(re-find #"(?i)perl version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the perl programming language"}))))))

(deftest check-digest-version-test
  (testing "Digest version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)digest version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Digest/1.20"})))))
    (is (empty? (filter #(re-find #"(?i)digest version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the digest module"}))))))

(deftest check-httptiny-version-test
  (testing "HTTP::Tiny version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)http::tiny version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via HTTP::Tiny/0.088"})))))
    (is (empty? (filter #(re-find #"(?i)http::tiny version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the http::tiny client"}))))))

(deftest check-carp-version-test
  (testing "Carp version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)carp version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Carp/1.52"})))))
    (is (empty? (filter #(re-find #"(?i)carp version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the carp module"}))))))

(deftest check-scalar-version-test
  (testing "Scalar version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)scalar version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Scalar/1.38"})))))
    (is (empty? (filter #(re-find #"(?i)scalar version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the scalar type"}))))))

(deftest check-list-version-test
  (testing "List version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)list version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via List/1.63"})))))
    (is (empty? (filter #(re-find #"(?i)list version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the list utility"}))))))

(deftest check-exporter-version-test
  (testing "Exporter version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)exporter version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Exporter/5.76"})))))
    (is (empty? (filter #(re-find #"(?i)exporter version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the exporter module"}))))))

(deftest check-getopt-version-test
  (testing "Getopt version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)getopt version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Getopt/2.33"})))))
    (is (empty? (filter #(re-find #"(?i)getopt version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the getopt module"}))))))

(deftest check-findbin-version-test
  (testing "FindBin version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)findbin version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via FindBin/1.53"})))))
    (is (empty? (filter #(re-find #"(?i)findbin version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the findbin module"}))))))

(deftest check-file-version-test
  (testing "File version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)file version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via File/5.45"})))))
    (is (empty? (filter #(re-find #"(?i)file version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the file module"}))))))

(deftest check-glob-version-test
  (testing "Glob version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)glob version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Glob/2.31"})))))
    (is (empty? (filter #(re-find #"(?i)glob version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the glob utility"}))))))

(deftest check-cwd-version-test
  (testing "Cwd version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)cwd version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Cwd/3.89"})))))
    (is (empty? (filter #(re-find #"(?i)cwd version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the cwd module"}))))))

(deftest check-extutils-version-test
  (testing "ExtUtils version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)extutils version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via ExtUtils/7.74"})))))
    (is (empty? (filter #(re-find #"(?i)extutils version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the extutils toolkit"}))))))

(deftest check-testharness-version-test
  (testing "Test-Harness version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)test-harness version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Test-Harness/3.50"})))))
    (is (empty? (filter #(re-find #"(?i)test-harness version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the test-harness module"}))))))

(deftest check-time-version-test
  (testing "Time version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)time version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Time/1.32"})))))
    (is (empty? (filter #(re-find #"(?i)time version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the time module"}))))))

(deftest check-pod-version-test
  (testing "Pod version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)pod version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Pod/4.22"})))))
    (is (empty? (filter #(re-find #"(?i)pod version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the pod module"}))))))

(deftest check-benchmark-version-test
  (testing "Benchmark version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)benchmark version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Benchmark/1.18"})))))
    (is (empty? (filter #(re-find #"(?i)benchmark version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the benchmark module"}))))))

(deftest check-b-version-test
  (testing "B version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)b version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via B/1.89"})))))
    (is (empty? (filter #(re-find #"(?i)b version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the b module"}))))))

(deftest check-develppport-version-test
  (testing "Devel-PPPort version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)devel-ppport version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Devel-PPPort/3.71"})))))
    (is (empty? (filter #(re-find #"(?i)devel-ppport version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the devel-ppport module"}))))))

(deftest check-math-version-test
  (testing "Math version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)math version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Math/0.12"})))))
    (is (empty? (filter #(re-find #"(?i)math version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the math library"}))))))

(deftest check-posix-version-test
  (testing "POSIX version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)posix version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via POSIX/1.38"})))))
    (is (empty? (filter #(re-find #"(?i)posix version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the posix standard"}))))))

(deftest check-socket-version-test
  (testing "Socket version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)socket version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Socket/2.036"})))))
    (is (empty? (filter #(re-find #"(?i)socket version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the socket module"}))))))

(deftest check-io-version-test
  (testing "IO version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)io version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via IO/0.21"})))))
    (is (empty? (filter #(re-find #"(?i)io version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the io module"}))))))

(deftest check-expect-version-test
  (testing "Expect version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)expect version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Expect/5.45"})))))
    (is (empty? (filter #(re-find #"(?i)expect version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the expect utility"}))))))

(deftest check-config-version-test
  (testing "Config version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)config version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Config/5.06"})))))
    (is (empty? (filter #(re-find #"(?i)config version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the config module"}))))))

(deftest check-locale-version-test
  (testing "Locale version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)locale version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Locale/5.01"})))))
    (is (empty? (filter #(re-find #"(?i)locale version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the locale module"}))))))

(deftest check-memoize-version-test
  (testing "Memoize version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)memoize version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Memoize/1.05"})))))
    (is (empty? (filter #(re-find #"(?i)memoize version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the memoize module"}))))))

(deftest check-bssolv-version-test
  (testing "BSSolv version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)bssolv version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via BSSolv/1.03"})))))
    (is (empty? (filter #(re-find #"(?i)bssolv version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the bssolv module"}))))))

(deftest check-bsversion-version-test
  (testing "BSVersion version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)bsversion version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via BSVersion/1.21"})))))
    (is (empty? (filter #(re-find #"(?i)bsversion version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the bsversion module"}))))))

(deftest check-class-version-test
  (testing "Class version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)class version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Class/1.75"})))))
    (is (empty? (filter #(re-find #"(?i)class version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the class system"}))))))

(deftest check-data-version-test
  (testing "Data version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)data version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Data/0.32"})))))
    (is (empty? (filter #(re-find #"(?i)data version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the data module"}))))))

(deftest check-diag-version-test
  (testing "Diag version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)diag version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Diag/5.07"})))))
    (is (empty? (filter #(re-find #"(?i)diag version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the diag module"}))))))

(deftest check-ebcdic-version-test
  (testing "EBCDIC version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)ebcdic version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via EBCDIC/2.14"})))))
    (is (empty? (filter #(re-find #"(?i)ebcdic version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the ebcdic encoding"}))))))

(deftest check-fence-version-test
  (testing "Fence version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)fence version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Fence/1.30"})))))
    (is (empty? (filter #(re-find #"(?i)fence version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the fence module"}))))))

(deftest check-getopt2-version-test
  (testing "Getopt2 version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)getopt2 version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Getopt2/2.33"})))))
    (is (empty? (filter #(re-find #"(?i)getopt2 version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the getopt2 module"}))))))

(deftest check-hash-version-test
  (testing "Hash version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)hash version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Hash/1.38"})))))
    (is (empty? (filter #(re-find #"(?i)hash version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the hash module"}))))))

(deftest check-host-version-test
  (testing "Host version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)host version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Host/6.21"})))))
    (is (empty? (filter #(re-find #"(?i)host version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the host module"}))))))

(deftest check-ioasync-version-test
  (testing "IO-Async version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)io-async version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via IO-Async/0.04"})))))
    (is (empty? (filter #(re-find #"(?i)io-async version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the io-async module"}))))))

(deftest check-ioselect-version-test
  (testing "IO-Select version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)io-select version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via IO-Select/1.58"})))))
    (is (empty? (filter #(re-find #"(?i)io-select version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the io-select module"}))))))

(deftest check-mime-version-test
  (testing "MIME version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)mime version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via MIME/3.27"})))))
    (is (empty? (filter #(re-find #"(?i)mime version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the mime type"}))))))

(deftest check-msgpack-version-test
  (testing "MsgPack version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)msgpack version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via MsgPack/1.09"})))))
    (is (empty? (filter #(re-find #"(?i)msgpack version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the msgpack format"}))))))

(deftest check-op-version-test
  (testing "Op version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)op version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Op/0.35"})))))
    (is (empty? (filter #(re-find #"(?i)op version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the op module"}))))))

(deftest check-oo-version-test
  (testing "OO version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)oo version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via OO/0.17"})))))
    (is (empty? (filter #(re-find #"(?i)oo version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the oo module"}))))))

(deftest check-oodim-version-test
  (testing "OODim version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)oodim version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via OODim/1.03"})))))
    (is (empty? (filter #(re-find #"(?i)oodim version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the oodim module"}))))))

(deftest check-opi-version-test
  (testing "OPI version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)opi version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via OPI/2.14"})))))
    (is (empty? (filter #(re-find #"(?i)opi version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the opi module"}))))))

(deftest check-os-version-test
  (testing "OS version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)os version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via OS/3.45"})))))
    (is (empty? (filter #(re-find #"(?i)os version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the os module"}))))))

(deftest check-perlio-version-test
  (testing "PerlIO version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)perlio version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via PerlIO/1.10"})))))
    (is (empty? (filter #(re-find #"(?i)perlio version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the perlio layer"}))))))

(deftest check-pokemon-version-test
  (testing "Pokemon version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)pokemon version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Pokemon/2.20"})))))
    (is (empty? (filter #(re-find #"(?i)pokemon version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the pokemon module"}))))))

(deftest check-lighttpd-version-test
  (testing "lighttpd version flagged; plain mention clean"
    (is (= 1 (count (filter #(re-find #"(?i)lighttpd version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via lighttpd/1.4.74"})))))
    (is (empty? (filter #(re-find #"(?i)lighttpd version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the lighttpd web server"}))))))

(deftest check-version-batch-10-test
  (testing "10 batched version patterns flagged; plain mentions clean"
    (is (= 1 (count (filter #(re-find #"(?i)haproxy version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via HAProxy/2.8"})))))
    (is (empty? (filter #(re-find #"(?i)haproxy version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the haproxy config"}))))
    (is (= 1 (count (filter #(re-find #"(?i)traefik version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Traefik/3.1"})))))
    (is (empty? (filter #(re-find #"(?i)traefik version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the traefik dashboard"}))))
    (is (= 1 (count (filter #(re-find #"(?i)envoy version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Envoy/1.31"})))))
    (is (empty? (filter #(re-find #"(?i)envoy version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the envoy config"}))))
    (is (= 1 (count (filter #(re-find #"(?i)cherokee version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Cherokee/1.2"})))))
    (is (empty? (filter #(re-find #"(?i)cherokee version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the cherokee web server"}))))
    (is (= 1 (count (filter #(re-find #"(?i)proxygen version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Proxygen/10.4"})))))
    (is (empty? (filter #(re-find #"(?i)proxygen version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the proxygen library"}))))
    (is (= 1 (count (filter #(re-find #"(?i)istio version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Istio/1.24"})))))
    (is (empty? (filter #(re-find #"(?i)istio version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "istioctl analyze"}))))
    (is (= 1 (count (filter #(re-find #"(?i)gunicorn version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Gunicorn/22.0"})))))
    (is (empty? (filter #(re-find #"(?i)gunicorn version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the gunicorn config"}))))
    (is (= 1 (count (filter #(re-find #"(?i)unicorn version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Unicorn/6.1"})))))
    (is (empty? (filter #(re-find #"(?i)unicorn version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "unicorn the symbol"}))))
    (is (= 1 (count (filter #(re-find #"(?i)puma version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Puma/6.4"})))))
    (is (empty? (filter #(re-find #"(?i)puma version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "puma the animal in the doc"}))))
    (is (= 1 (count (filter #(re-find #"(?i)passenger version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Passenger/6.0"})))))
    (is (empty? (filter #(re-find #"(?i)passenger version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "passenger list"}))))))

(deftest open-gap-families-test
  (testing "open-gap 10 families: new families + variant counts"
    (is (>= (count active/sqli-payloads) 13))
    (is (>= (count active/xss-payloads) 14))
    (is (>= (count active/cmdi-payloads) 11))
    (is (>= (count active/trav-payloads) 15))
    (is (>= (count active/crlf-payloads) 12))
    (is (>= (count active/ssrf-payloads) 3))
    (is (>= (count active/rfi-payloads) 3))
    (is (>= (count active/deser-payloads) 3))
    (is (some #(= "40025" (:rule-id %)) active/rule-families))
    (is (some #(= "40026" (:rule-id %)) active/rule-families))
    (is (some #(= "40027" (:rule-id %)) active/rule-families))
    (is (= "CWE-918" (:cwe (first (filter #(= "40025" (:rule-id %)) active/rule-families)))))
    (is (= "CWE-502" (:cwe (first (filter #(= "40027" (:rule-id %)) active/rule-families)))))
    (is (>= (count active/rule-families) 13))))

(deftest nvd-import-catalog-test
  (testing "cwe-cve catalog covers all rule CWEs (imported, not invented)"
    (let [filesystem (fs-host/host-filesystem
                       {:root (.getCanonicalPath (java.io.File. "."))})
          catalog (edn/read-string (fs/read filesystem "resources/zap_proxy/catalog/cwe-cve.edn"))
          entries (:entries catalog)
          rule-cwes (set (map #(get % :zap-proxy.rule/cwe) (edn/read-string (fs/read filesystem "resources/zap_proxy/rules/rules.edn"))))]
      (is (every? #(contains? entries %) rule-cwes))
      (is (contains? entries "CWE-918"))
      (is (contains? entries "CWE-502"))
      (is (pos? (count (:cve-ids (get entries "CWE-918")))))
      (is (pos? (count (:cve-ids (get entries "CWE-502")))))
      (is (every? #(re-matches #"CVE-\d{4}-\d+" %) (mapcat :cve-ids (vals entries)))))))

(deftest check-version-batch2-10-test
  (testing "10 batched version patterns flagged; plain mentions clean"
    (is (= 1 (count (filter #(re-find #"(?i)express version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Express/4.19"})))))
    (is (empty? (filter #(re-find #"(?i)express version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the express route"}))))
    (is (= 1 (count (filter #(re-find #"(?i)fastify version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Fastify/5.2"})))))
    (is (empty? (filter #(re-find #"(?i)fastify version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the fastify plugin"}))))
    (is (= 1 (count (filter #(re-find #"(?i)koa version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Koa/2.16"})))))
    (is (empty? (filter #(re-find #"(?i)koa version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the koa middleware"}))))
    (is (= 1 (count (filter #(re-find #"(?i)flask version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Flask/3.1"})))))
    (is (empty? (filter #(re-find #"(?i)flask version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the flask app factory"}))))
    (is (= 1 (count (filter #(re-find #"(?i)django version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Django/5.1"})))))
    (is (empty? (filter #(re-find #"(?i)django version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the django settings"}))))
    (is (= 1 (count (filter #(re-find #"(?i)rails version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Rails/7.2"})))))
    (is (empty? (filter #(re-find #"(?i)rails version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the rails guide"}))))
    (is (= 1 (count (filter #(re-find #"(?i)laravel version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Laravel/11.30"})))))
    (is (empty? (filter #(re-find #"(?i)laravel version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the laravel docs"}))))
    (is (= 1 (count (filter #(re-find #"(?i)symfony version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Symfony/7.2"})))))
    (is (empty? (filter #(re-find #"(?i)symfony version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the symfony console"}))))
    (is (= 1 (count (filter #(re-find #"(?i)spring version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Spring/6.2"})))))
    (is (empty? (filter #(re-find #"(?i)spring version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "spring boot app"}))))
    (is (= 1 (count (filter #(re-find #"(?i)aspnet version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via ASP.NET/9.0"})))))
    (is (empty? (filter #(re-find #"(?i)aspnet version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the aspnet core docs"}))))))

(deftest check-version-batch3-10-test
  (testing "10 batched version patterns flagged; plain mentions clean"
    (is (= 1 (count (filter #(re-find #"(?i)wordpress version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via WordPress/6.7"})))))
    (is (empty? (filter #(re-find #"(?i)wordpress version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the wordpress theme"}))))
    (is (= 1 (count (filter #(re-find #"(?i)drupal version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Drupal/11.1"})))))
    (is (empty? (filter #(re-find #"(?i)drupal version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the drupal module"}))))
    (is (= 1 (count (filter #(re-find #"(?i)joomla version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Joomla/5.2"})))))
    (is (empty? (filter #(re-find #"(?i)joomla version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the joomla admin"}))))
    (is (= 1 (count (filter #(re-find #"(?i)nextjs version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via NextJS/15.1"})))))
    (is (empty? (filter #(re-find #"(?i)nextjs version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the nextjs app dir"}))))
    (is (= 1 (count (filter #(re-find #"(?i)nuxt version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Nuxt/3.15"})))))
    (is (empty? (filter #(re-find #"(?i)nuxt version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the nuxt component"}))))
    (is (= 1 (count (filter #(re-find #"(?i)hapi version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Hapi/21.4"})))))
    (is (empty? (filter #(re-find #"(?i)hapi version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the hapi route"}))))
    (is (= 1 (count (filter #(re-find #"(?i)adonis version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Adonis/6.1"})))))
    (is (empty? (filter #(re-find #"(?i)adonis version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the adonis template"}))))
    (is (= 1 (count (filter #(re-find #"(?i)cakephp version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via CakePHP/5.1"})))))
    (is (empty? (filter #(re-find #"(?i)cakephp version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the cakephp bake"}))))
    (is (= 1 (count (filter #(re-find #"(?i)codeigniter version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via CodeIgniter/4.6"})))))
    (is (empty? (filter #(re-find #"(?i)codeigniter version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the codeigniter controller"}))))
    (is (= 1 (count (filter #(re-find #"(?i)slim version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Slim/4.12"})))))
    (is (empty? (filter #(re-find #"(?i)slim version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the slim router"}))))))

(deftest check-version-batch4-10-test
  (testing "10 batched version patterns flagged; plain mentions clean"
    (is (= 1 (count (filter #(re-find #"(?i)magento version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Magento/2.4"})))))
    (is (empty? (filter #(re-find #"(?i)magento version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the magento admin"}))))
    (is (= 1 (count (filter #(re-find #"(?i)prestashop version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via PrestaShop/8.1"})))))
    (is (empty? (filter #(re-find #"(?i)prestashop version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the prestashop theme"}))))
    (is (= 1 (count (filter #(re-find #"(?i)opencart version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via OpenCart/4.0"})))))
    (is (empty? (filter #(re-find #"(?i)opencart version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the opencart extension"}))))
    (is (= 1 (count (filter #(re-find #"(?i)saleor version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Saleor/3.20"})))))
    (is (empty? (filter #(re-find #"(?i)saleor version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the saleor dashboard"}))))
    (is (= 1 (count (filter #(re-find #"(?i)medusa version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Medusa/2.0"})))))
    (is (empty? (filter #(re-find #"(?i)medusa version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the medusa plugin"}))))
    (is (= 1 (count (filter #(re-find #"(?i)strapi version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Strapi/5.8"})))))
    (is (empty? (filter #(re-find #"(?i)strapi version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the strapi content type"}))))
    (is (= 1 (count (filter #(re-find #"(?i)ghost version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Ghost/5.9"})))))
    (is (empty? (filter #(re-find #"(?i)ghost version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the ghost theme"}))))
    (is (= 1 (count (filter #(re-find #"(?i)keystone version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Keystone/6.2"})))))
    (is (empty? (filter #(re-find #"(?i)keystone version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the keystone list"}))))
    (is (= 1 (count (filter #(re-find #"(?i)payload version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Payload/3.2"})))))
    (is (empty? (filter #(re-find #"(?i)payload version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the payload collection"}))))
    (is (= 1 (count (filter #(re-find #"(?i)sanity version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Sanity/3.5"})))))
    (is (empty? (filter #(re-find #"(?i)sanity version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the sanity schema"}))))))

(deftest check-version-batch5-10-test
  (testing "10 batched version patterns flagged; plain mentions clean"
    (is (= 1 (count (filter #(re-find #"(?i)redis version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Redis/7.2"})))))
    (is (empty? (filter #(re-find #"(?i)redis version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the redis cache"}))))
    (is (= 1 (count (filter #(re-find #"(?i)postgres version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Postgres/16.1"})))))
    (is (empty? (filter #(re-find #"(?i)postgres version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the postgres database"}))))
    (is (= 1 (count (filter #(re-find #"(?i)mysql version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via MySQL/8.0"})))))
    (is (empty? (filter #(re-find #"(?i)mysql version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the mysql server"}))))
    (is (= 1 (count (filter #(re-find #"(?i)mongodb version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via MongoDB/7.0"})))))
    (is (empty? (filter #(re-find #"(?i)mongodb version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the mongodb atlas docs"}))))
    (is (= 1 (count (filter #(re-find #"(?i)mariadb version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via MariaDB/11.4"})))))
    (is (empty? (filter #(re-find #"(?i)mariadb version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the mariadb docker image"}))))
    (is (= 1 (count (filter #(re-find #"(?i)elasticsearch version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Elasticsearch/8.12"})))))
    (is (empty? (filter #(re-find #"(?i)elasticsearch version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the elasticsearch index"}))))
    (is (= 1 (count (filter #(re-find #"(?i)solr version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Solr/9.5"})))))
    (is (empty? (filter #(re-find #"(?i)solr version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the solr collection"}))))
    (is (= 1 (count (filter #(re-find #"(?i)typesense version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Typesense/26.0"})))))
    (is (empty? (filter #(re-find #"(?i)typesense version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the typesense collection"}))))
    (is (= 1 (count (filter #(re-find #"(?i)meilisearch version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Meilisearch/1.10"})))))
    (is (empty? (filter #(re-find #"(?i)meilisearch version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the meilisearch index"}))))
    (is (= 1 (count (filter #(re-find #"(?i)sphinx version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Sphinx/7.2"})))))
    (is (empty? (filter #(re-find #"(?i)sphinx version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the sphinx docs"}))))))

(deftest check-version-batch6-10-test
  (testing "10 batched version patterns flagged; plain mentions clean"
    (is (= 1 (count (filter #(re-find #"(?i)docker version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Docker/27.3"})))))
    (is (empty? (filter #(re-find #"(?i)docker version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the docker image"}))))
    (is (= 1 (count (filter #(re-find #"(?i)kubernetes version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Kubernetes/1.31"})))))
    (is (empty? (filter #(re-find #"(?i)kubernetes version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the kubernetes cluster"}))))
    (is (= 1 (count (filter #(re-find #"(?i)prometheus version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Prometheus/2.55"})))))
    (is (empty? (filter #(re-find #"(?i)prometheus version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the prometheus scrape"}))))
    (is (= 1 (count (filter #(re-find #"(?i)grafana version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Grafana/11.3"})))))
    (is (empty? (filter #(re-find #"(?i)grafana version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the grafana dashboard"}))))
    (is (= 1 (count (filter #(re-find #"(?i)jenkins version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Jenkins/2.462"})))))
    (is (empty? (filter #(re-find #"(?i)jenkins version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the jenkins pipeline"}))))
    (is (= 1 (count (filter #(re-find #"(?i)gitlab version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via GitLab/17.6"})))))
    (is (empty? (filter #(re-find #"(?i)gitlab version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the gitlab runner"}))))
    (is (= 1 (count (filter #(re-find #"(?i)github version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via GitHub/3.9"})))))
    (is (empty? (filter #(re-find #"(?i)github version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the github action"}))))
    (is (= 1 (count (filter #(re-find #"(?i)node version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Node/22.12"})))))
    (is (empty? (filter #(re-find #"(?i)node version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the node modules"}))))
    (is (= 1 (count (filter #(re-find #"(?i)deno version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Deno/2.0"})))))
    (is (empty? (filter #(re-find #"(?i)deno version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the deno Deploy docs"}))))
    (is (= 1 (count (filter #(re-find #"(?i)bun version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Bun/1.1"})))))
    (is (empty? (filter #(re-find #"(?i)bun version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the bun install"}))))))

(deftest check-version-batch7-10-test
  (testing "10 batched version patterns flagged; plain mentions clean"
    (is (= 1 (count (filter #(re-find #"(?i)php version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via PHP/8.3"})))))
    (is (empty? (filter #(re-find #"(?i)php version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the phpinfo page"}))))
    (is (= 1 (count (filter #(re-find #"(?i)python version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Python/3.12"})))))
    (is (empty? (filter #(re-find #"(?i)python version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the python path"}))))
    (is (= 1 (count (filter #(re-find #"(?i)ruby version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Ruby/3.3"})))))
    (is (empty? (filter #(re-find #"(?i)ruby version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the ruby gem"}))))
    (is (= 1 (count (filter #(re-find #"(?i)go version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Go/1.22"})))))
    (is (empty? (filter #(re-find #"(?i)go version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "go to the next page"}))))
    (is (= 1 (count (filter #(re-find #"(?i)java version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Java/21.0"})))))
    (is (empty? (filter #(re-find #"(?i)java version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the java package"}))))
    (is (= 1 (count (filter #(re-find #"(?i)rust version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Rust/1.82"})))))
    (is (empty? (filter #(re-find #"(?i)rust version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the rust crate"}))))
    (is (= 1 (count (filter #(re-find #"(?i)clojure version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Clojure/1.11"})))))
    (is (empty? (filter #(re-find #"(?i)clojure version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the clojure REPL"}))))
    (is (= 1 (count (filter #(re-find #"(?i)scala version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Scala/3.4"})))))
    (is (empty? (filter #(re-find #"(?i)scala version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the scala compiler"}))))
    (is (= 1 (count (filter #(re-find #"(?i)dotnet version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Dotnet/8.0"})))))
    (is (empty? (filter #(re-find #"(?i)dotnet version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the dotnet SDK"}))))
    (is (= 1 (count (filter #(re-find #"(?i)erlang version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Erlang/26.2"})))))
    (is (empty? (filter #(re-find #"(?i)erlang version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the erlang node"}))))))

(deftest check-version-batch8-10-test
  (testing "10 batched version patterns flagged; plain mentions clean"
    (is (= 1 (count (filter #(re-find #"(?i)play version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Play/3.0"})))))
    (is (empty? (filter #(re-find #"(?i)play version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the play framework"}))))
    (is (= 1 (count (filter #(re-find #"(?i)akka version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Akka/2.9"})))))
    (is (empty? (filter #(re-find #"(?i)akka version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the akka actor"}))))
    (is (= 1 (count (filter #(re-find #"(?i)quarkus version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Quarkus/3.7"})))))
    (is (empty? (filter #(re-find #"(?i)quarkus version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the quarkus extension"}))))
    (is (= 1 (count (filter #(re-find #"(?i)micronaut version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Micronaut/4.2"})))))
    (is (empty? (filter #(re-find #"(?i)micronaut version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the micronaut docs"}))))
    (is (= 1 (count (filter #(re-find #"(?i)vertx version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Vertx/4.5"})))))
    (is (empty? (filter #(re-find #"(?i)vertx version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the vertx verticle"}))))
    (is (= 1 (count (filter #(re-find #"(?i)dropwizard version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Dropwizard/4.0"})))))
    (is (empty? (filter #(re-find #"(?i)dropwizard version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the dropwizard config"}))))
    (is (= 1 (count (filter #(re-find #"(?i)jooby version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Jooby/3.5"})))))
    (is (empty? (filter #(re-find #"(?i)jooby version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the jooby module"}))))
    (is (= 1 (count (filter #(re-find #"(?i)helidon version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Helidon/4.1"})))))
    (is (empty? (filter #(re-find #"(?i)helidon version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the helidon webserver"}))))
    (is (= 1 (count (filter #(re-find #"(?i)openliberty version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via OpenLiberty/24.0"})))))
    (is (empty? (filter #(re-find #"(?i)openliberty version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the openliberty server"}))))
    (is (= 1 (count (filter #(re-find #"(?i)kotlin version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Kotlin/1.9"})))))
    (is (empty? (filter #(re-find #"(?i)kotlin version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the kotlin DSL"}))))))

(deftest check-version-batch9-10-test
  (testing "10 batched version patterns flagged; plain mentions clean"
    (is (= 1 (count (filter #(re-find #"(?i)feathers version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Feathers/5.0"})))))
    (is (empty? (filter #(re-find #"(?i)feathers version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the feathers service"}))))
    (is (= 1 (count (filter #(re-find #"(?i)loopback version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via LoopBack/4.0"})))))
    (is (empty? (filter #(re-find #"(?i)loopback version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the loopback model"}))))
    (is (= 1 (count (filter #(re-find #"(?i)meteor version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Meteor/2.16"})))))
    (is (empty? (filter #(re-find #"(?i)meteor version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the meteor collection"}))))
    (is (= 1 (count (filter #(re-find #"(?i)blitz version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Blitz/2.2"})))))
    (is (empty? (filter #(re-find #"(?i)blitz version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the blitz query"}))))
    (is (= 1 (count (filter #(re-find #"(?i)redwood version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Redwood/6.5"})))))
    (is (empty? (filter #(re-find #"(?i)redwood version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the redwood cell"}))))
    (is (= 1 (count (filter #(re-find #"(?i)wasp version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Wasp/0.16"})))))
    (is (empty? (filter #(re-find #"(?i)wasp version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the wasp app"}))))
    (is (= 1 (count (filter #(re-find #"(?i)expo version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Expo/52.0"})))))
    (is (empty? (filter #(re-find #"(?i)expo version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the expo routing"}))))
    (is (= 1 (count (filter #(re-find #"(?i)ionic version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Ionic/8.0"})))))
    (is (empty? (filter #(re-find #"(?i)ionic version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the ionic modal"}))))
    (is (= 1 (count (filter #(re-find #"(?i)cordova version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Cordova/13.0"})))))
    (is (empty? (filter #(re-find #"(?i)cordova version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the cordova plugin"}))))
    (is (= 1 (count (filter #(re-find #"(?i)electron version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Electron/33.0"})))))
    (is (empty? (filter #(re-find #"(?i)electron version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the electron app"}))))))

(deftest check-version-batch10-10-test
  (testing "10 batched version patterns flagged; plain mentions clean"
    (is (= 1 (count (filter #(re-find #"(?i)angular version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Angular/19.0"})))))
    (is (empty? (filter #(re-find #"(?i)angular version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the angular component"}))))
    (is (= 1 (count (filter #(re-find #"(?i)react version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via React/19.0"})))))
    (is (empty? (filter #(re-find #"(?i)react version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the react hook"}))))
    (is (= 1 (count (filter #(re-find #"(?i)vue version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Vue/3.5"})))))
    (is (empty? (filter #(re-find #"(?i)vue version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the vue router"}))))
    (is (= 1 (count (filter #(re-find #"(?i)svelte version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Svelte/5.10"})))))
    (is (empty? (filter #(re-find #"(?i)svelte version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the svelte store"}))))
    (is (= 1 (count (filter #(re-find #"(?i)backbone version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Backbone/1.6"})))))
    (is (empty? (filter #(re-find #"(?i)backbone version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the backbone view"}))))
    (is (= 1 (count (filter #(re-find #"(?i)ember version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Ember/5.12"})))))
    (is (empty? (filter #(re-find #"(?i)ember version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the ember route"}))))
    (is (= 1 (count (filter #(re-find #"(?i)knockout version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Knockout/3.5"})))))
    (is (empty? (filter #(re-find #"(?i)knockout version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the knockout binding"}))))
    (is (= 1 (count (filter #(re-find #"(?i)dojo version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Dojo/1.17"})))))
    (is (empty? (filter #(re-find #"(?i)dojo version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the dojo widget"}))))
    (is (= 1 (count (filter #(re-find #"(?i)preact version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Preact/10.22"})))))
    (is (empty? (filter #(re-find #"(?i)preact version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the preact component"}))))
    (is (= 1 (count (filter #(re-find #"(?i)solid version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Solid/1.9"})))))
    (is (empty? (filter #(re-find #"(?i)solid version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the solid signal"}))))))

(deftest check-version-batch11-10-test
  (testing "10 batched version patterns flagged; plain mentions clean"
    (is (= 1 (count (filter #(re-find #"(?i)nextcloud version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Nextcloud/29.0"})))))
    (is (empty? (filter #(re-find #"(?i)nextcloud version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the nextcloud app"}))))
    (is (= 1 (count (filter #(re-find #"(?i)owncloud version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via ownCloud/10.13"})))))
    (is (empty? (filter #(re-find #"(?i)owncloud version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the owncloud share"}))))
    (is (= 1 (count (filter #(re-find #"(?i)opensearch version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via OpenSearch/2.13"})))))
    (is (empty? (filter #(re-find #"(?i)opensearch version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the opensearch index"}))))
    (is (= 1 (count (filter #(re-find #"(?i)logstash version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Logstash/8.15"})))))
    (is (empty? (filter #(re-find #"(?i)logstash version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the logstash pipeline"}))))
    (is (= 1 (count (filter #(re-find #"(?i)kibana version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Kibana/8.15"})))))
    (is (empty? (filter #(re-find #"(?i)kibana version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the kibana dashboard"}))))
    (is (= 1 (count (filter #(re-find #"(?i)filebeat version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Filebeat/8.15"})))))
    (is (empty? (filter #(re-find #"(?i)filebeat version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the filebeat input"}))))
    (is (= 1 (count (filter #(re-find #"(?i)fluentd version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Fluentd/1.17"})))))
    (is (empty? (filter #(re-find #"(?i)fluentd version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the fluentd buffer"}))))
    (is (= 1 (count (filter #(re-find #"(?i)consul version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Consul/1.19"})))))
    (is (empty? (filter #(re-find #"(?i)consul version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the consul agent"}))))
    (is (= 1 (count (filter #(re-find #"(?i)vault version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Vault/1.17"})))))
    (is (empty? (filter #(re-find #"(?i)vault version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the vault policy"}))))
    (is (= 1 (count (filter #(re-find #"(?i)etcd version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via etcd/3.5"})))))
    (is (empty? (filter #(re-find #"(?i)etcd version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the etcd keyspace"}))))))

(deftest check-version-batch12-10-test
  (testing "10 batched version patterns flagged; plain mentions clean"
    (is (= 1 (count (filter #(re-find #"(?i)shopify version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Shopify/2.0"})))))
    (is (empty? (filter #(re-find #"(?i)shopify version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the shopify store"}))))
    (is (= 1 (count (filter #(re-find #"(?i)wix version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Wix/3.0"})))))
    (is (empty? (filter #(re-find #"(?i)wix version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the wix site"}))))
    (is (= 1 (count (filter #(re-find #"(?i)squarespace version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Squarespace/7.1"})))))
    (is (empty? (filter #(re-find #"(?i)squarespace version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the squarespace template"}))))
    (is (= 1 (count (filter #(re-find #"(?i)webflow version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Webflow/4.0"})))))
    (is (empty? (filter #(re-find #"(?i)webflow version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the webflow CMS"}))))
    (is (= 1 (count (filter #(re-find #"(?i)framer version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Framer/2.1"})))))
    (is (empty? (filter #(re-find #"(?i)framer version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the framer canvas"}))))
    (is (= 1 (count (filter #(re-find #"(?i)shopware version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Shopware/6.6"})))))
    (is (empty? (filter #(re-find #"(?i)shopware version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the shopware shop"}))))
    (is (= 1 (count (filter #(re-find #"(?i)commercetools version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Commercetools/3.0"})))))
    (is (empty? (filter #(re-find #"(?i)commercetools version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the commercetools project"}))))
    (is (= 1 (count (filter #(re-find #"(?i)spryker version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Spryker/2.5"})))))
    (is (empty? (filter #(re-find #"(?i)spryker version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the spryker storefront"}))))
    (is (= 1 (count (filter #(re-find #"(?i)sulu version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Sulu/2.6"})))))
    (is (empty? (filter #(re-find #"(?i)sulu version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the sulu admin"}))))
    (is (= 1 (count (filter #(re-find #"(?i)api-platform version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via API-Platform/3.3"})))))
    (is (empty? (filter #(re-find #"(?i)api-platform version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the api-platform docs"}))))))

(deftest check-version-batch13-10-test
  (testing "10 batched version patterns flagged; plain mentions clean"
    (is (= 1 (count (filter #(re-find #"(?i)matomo version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Matomo/5.1"})))))
    (is (empty? (filter #(re-find #"(?i)matomo version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the matomo tracker"}))))
    (is (= 1 (count (filter #(re-find #"(?i)plausible version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Plausible/5.0"})))))
    (is (empty? (filter #(re-find #"(?i)plausible version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the plausible script"}))))
    (is (= 1 (count (filter #(re-find #"(?i)umami version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Umami/2.8"})))))
    (is (empty? (filter #(re-find #"(?i)umami version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the umami dashboard"}))))
    (is (= 1 (count (filter #(re-find #"(?i)posthog version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via PostHog/1.140"})))))
    (is (empty? (filter #(re-find #"(?i)posthog version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the posthog snippet"}))))
    (is (= 1 (count (filter #(re-find #"(?i)mixpanel version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Mixpanel/2.50"})))))
    (is (empty? (filter #(re-find #"(?i)mixpanel version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the mixpanel SDK"}))))
    (is (= 1 (count (filter #(re-find #"(?i)amplitude version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Amplitude/1.0"})))))
    (is (empty? (filter #(re-find #"(?i)amplitude version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the amplitude events"}))))
    (is (= 1 (count (filter #(re-find #"(?i)hotjar version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Hotjar/3.0"})))))
    (is (empty? (filter #(re-find #"(?i)hotjar version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the hotjar heatmap"}))))
    (is (= 1 (count (filter #(re-find #"(?i)fullstory version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via FullStory/1.50"})))))
    (is (empty? (filter #(re-find #"(?i)fullstory version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the fullstory session"}))))
    (is (= 1 (count (filter #(re-find #"(?i)logrocket version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via LogRocket/7.0"})))))
    (is (empty? (filter #(re-find #"(?i)logrocket version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the logrocket player"}))))
    (is (= 1 (count (filter #(re-find #"(?i)sentry version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Sentry/24.11"})))))
    (is (empty? (filter #(re-find #"(?i)sentry version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the sentry DSN"}))))))

(deftest check-version-batch14-10-test
  (testing "10 batched version patterns flagged; plain mentions clean"
    (is (= 1 (count (filter #(re-find #"(?i)cloudflare version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Cloudflare/1.0"})))))
    (is (empty? (filter #(re-find #"(?i)cloudflare version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the cloudflare ray"}))))
    (is (= 1 (count (filter #(re-find #"(?i)akamai version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Akamai/2.0"})))))
    (is (empty? (filter #(re-find #"(?i)akamai version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the akamai edge"}))))
    (is (= 1 (count (filter #(re-find #"(?i)fastly version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Fastly/3.0"})))))
    (is (empty? (filter #(re-find #"(?i)fastly version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the fastly POP"}))))
    (is (= 1 (count (filter #(re-find #"(?i)cloudfront version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via CloudFront/4.0"})))))
    (is (empty? (filter #(re-find #"(?i)cloudfront version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the cloudfront distribution"}))))
    (is (= 1 (count (filter #(re-find #"(?i)incapsula version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Incapsula/2.5"})))))
    (is (empty? (filter #(re-find #"(?i)incapsula version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the incapsula cookie"}))))
    (is (= 1 (count (filter #(re-find #"(?i)sucuri version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Sucuri/1.2"})))))
    (is (empty? (filter #(re-find #"(?i)sucuri version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the sucuri block page"}))))
    (is (= 1 (count (filter #(re-find #"(?i)wordfence version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Wordfence/7.11"})))))
    (is (empty? (filter #(re-find #"(?i)wordfence version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the wordfence firewall"}))))
    (is (= 1 (count (filter #(re-find #"(?i)imperva version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Imperva/3.0"})))))
    (is (empty? (filter #(re-find #"(?i)imperva version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the imperva policy"}))))
    (is (= 1 (count (filter #(re-find #"(?i)vercel version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Vercel/2.0"})))))
    (is (empty? (filter #(re-find #"(?i)vercel version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the vercel deployment"}))))
    (is (= 1 (count (filter #(re-find #"(?i)netlify version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "Serving via Netlify/3.6"})))))
    (is (empty? (filter #(re-find #"(?i)netlify version" (str (:title %))) (passive/check-sensitive-info {:url "https://h/"} {:status 200 :headers {} :body "the netlify edge function"}))))))

(deftest blind-differential-test
  (testing "boolean differential skeleton for blind SQLi (no requests sent)"
    (is (true? (active/boolean-differential? {:status 200 :body "hello world"} {:status 500 :body "error"})))
    (is (true? (active/boolean-differential? {:status 200 :body "aaaaaaaaaaaaaaaa"} {:status 200 :body "a"})))
    (is (false? (active/boolean-differential? {:status 200 :body "same"} {:status 200 :body "same"})))
    (is (false? (active/boolean-differential? nil {:status 200 :body "x"})))
    (is (false? (active/boolean-differential? {:status 200 :body "x"} nil)))
    (let [sig (active/response-signature {:status 200 :body "hello world"})]
      (is (= 200 (:status sig)))
      (is (= 11 (:length sig)))
      (is (= "hello world" (:head sig))))
    (is (= 0 (:status (active/response-signature nil))))
    (let [ev (active/blind-sqli-evidence {:status 200 :body "aaaaaaaaaaaaaaaa"} {:status 500 :body "error"})]
      (is (string? ev))
      (is (some? (re-find #"boolean differential" ev))))
    (is (nil? (active/blind-sqli-evidence {:status 200 :body "same"} {:status 200 :body "same"})))))

(deftest blind-sqli-scan-test
  (testing "blind-sqli-scan with stub send-fn (exactly two sends)"
    (let [calls (atom 0)
          send-fn (fn [{:keys [url]}]
                    (swap! calls inc)
                    (if (some? (re-find #"zztrue" url))
                      {:status 200 :body "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
                      {:status 500 :body "error"}))
          f (active/blind-sqli-scan {:url "https://h/?q=1" :send-fn send-fn :param-name "q"})]
      (is (= 2 @calls))
      (is (some? f))
      (is (= 40012 (:rule-id f)))
      (is (= "CWE-89" (:cwe f)))
      (is (= "q" (:param f)))
      (is (some? (re-find #"boolean differential" (str (:evidence f))))))
    (let [send-fn (fn [_req] {:status 200 :body "same"})
          f (active/blind-sqli-scan {:url "https://h/?q=1" :send-fn send-fn :param-name "q"})]
      (is (nil? f)))
    (is (nil? (active/blind-sqli-scan {:url "https://h/" :send-fn nil :param-name "q"})))))

(deftest time-differential-test
  (testing "time-based differential (pure, no sleeping)"
    (is (true? (active/time-differential? 100 1500)))
    (is (true? (active/time-differential? 100 1200 1000)))
    (is (false? (active/time-differential? 100 500)))
    (is (false? (active/time-differential? nil 5000)))
    (is (false? (active/time-differential? 100 nil)))
    (let [ev (active/time-evidence 100 5000)]
      (is (string? ev))
      (is (some? (re-find #"time differential" ev))))
    (is (nil? (active/time-evidence 100 150)))
    (let [calls (atom 0)
          send-fn (fn [_req] (swap! calls inc) {:status 200 :body "ok"})
          f (active/time-sqli-scan {:send-fn send-fn :param-name "q" :baseline-ms 100 :probe-ms 5000})]
      (is (= 1 @calls))
      (is (some? f))
      (is (= "SQL Injection (time-based)" (:title f))))
    (let [send-fn (fn [_req] {:status 200 :body "ok"})
          f (active/time-sqli-scan {:send-fn send-fn :param-name "q" :baseline-ms 100 :probe-ms 150})]
      (is (nil? f)))))

(deftest check-dom-xss-sink-test
  (testing "DOM XSS sink flagged; benign mentions clean"
    (is (= 1 (count (filter #(re-find #"DOM XSS sink" (str (:title %))) (passive/check-dom-xss-sink {:url "https://h/"} {:body "el.innerHTML = location.hash"})))))
    (is (= 1 (count (filter #(re-find #"DOM XSS sink" (str (:title %))) (passive/check-dom-xss-sink {:url "https://h/"} {:body "document.write(userInput)"})))))
    (is (= 1 (count (filter #(re-find #"DOM XSS sink" (str (:title %))) (passive/check-dom-xss-sink {:url "https://h/"} {:body "eval(input)"})))))
    (is (= 1 (count (filter #(re-find #"DOM XSS sink" (str (:title %))) (passive/check-dom-xss-sink {:url "https://h/"} {:body "el.insertAdjacentHTML(\"beforeend\", data)"})))))
    (is (= 1 (count (filter #(re-find #"DOM XSS sink" (str (:title %))) (passive/check-dom-xss-sink {:url "https://h/"} {:body "setTimeout(\"alert(1)\", 100)"})))))
    (is (empty? (filter #(re-find #"DOM XSS sink" (str (:title %))) (passive/check-dom-xss-sink {:url "https://h/"} {:body "el.textContent = value"}))))
    (is (empty? (filter #(re-find #"DOM XSS sink" (str (:title %))) (passive/check-dom-xss-sink {:url "https://h/"} {:body "the innerHTML property is documented"}))))
    (let [f (first (filter #(re-find #"DOM XSS sink" (str (:title %))) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "el.innerHTML = location.hash"})))]
      (is (some? f))
      (is (= "40028" (:rule-id f)))
      (is (= "CWE-79" (:cwe f))))))

(deftest check-js-library-version-test
  (testing "outdated JS library flagged; modern clean"
    (is (= 1 (count (filter #(re-find #"Outdated jQuery" (str (:title %))) (passive/check-js-library-version {:url "https://h/"} {:body "<script src=\"jquery-1.12.4.min.js\">"})))))
    (is (= 1 (count (filter #(re-find #"Outdated jQuery" (str (:title %))) (passive/check-js-library-version {:url "https://h/"} {:body "<script src=\"jquery-3.4.1.min.js\">"})))))
    (is (= 1 (count (filter #(re-find #"Outdated Bootstrap" (str (:title %))) (passive/check-js-library-version {:url "https://h/"} {:body "<script src=\"bootstrap-3.4.1.min.js\">"})))))
    (is (= 1 (count (filter #(re-find #"Outdated AngularJS" (str (:title %))) (passive/check-js-library-version {:url "https://h/"} {:body "<script src=\"angular-1.7.9.min.js\">"})))))
    (is (empty? (filter #(re-find #"Outdated" (str (:title %))) (passive/check-js-library-version {:url "https://h/"} {:body "<script src=\"jquery-3.7.1.min.js\">"}))))
    (is (empty? (filter #(re-find #"Outdated" (str (:title %))) (passive/check-js-library-version {:url "https://h/"} {:body "<script src=\"bootstrap-5.3.0.min.js\">"}))))
    (let [f (first (filter #(re-find #"Outdated jQuery" (str (:title %))) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "jquery-1.11.1.js"})))]
      (is (some? f))
      (is (= "10003" (:rule-id f)))
      (is (= "CWE-1104" (:cwe f))))))

(deftest check-ssti-reflection-test
  (testing "SSTI evaluated marker flagged; plain numbers clean"
    (is (= 1 (count (filter #(re-find #"SSTI" (str (:title %))) (passive/check-ssti-reflection {:url "https://h/"} {:body "7*7 = <b>49</b>"})))))
    (is (empty? (filter #(re-find #"SSTI" (str (:title %))) (passive/check-ssti-reflection {:url "https://h/"} {:body "the answer is 49"}))))
    (is (empty? (filter #(re-find #"SSTI" (str (:title %))) (passive/check-ssti-reflection {:url "https://h/"} {:body "try 7*7 yourself"}))))
    (let [f (first (filter #(re-find #"SSTI" (str (:title %))) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "7*7 = <b>49</b>"})))]
      (is (some? f))
      (is (= "40029" (:rule-id f)))
      (is (= "CWE-94" (:cwe f))))))

(deftest check-sourcemap-exposure-test
  (testing "source map referenced flagged; no map clean"
    (is (= 1 (count (filter #(re-find #"Source map" (str (:title %))) (passive/check-sourcemap-exposure {:url "https://h/"} {:body "//# sourceMappingURL=app.js.map"})))))
    (is (empty? (filter #(re-find #"Source map" (str (:title %))) (passive/check-sourcemap-exposure {:url "https://h/"} {:body "<script src=\"app.js\">"}))))
    (let [f (first (filter #(re-find #"Source map" (str (:title %))) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "sourceMappingURL=main.map"})))]
      (is (some? f))
      (is (= "40030" (:rule-id f)))
      (is (= "CWE-552" (:cwe f))))))

(deftest check-dotenv-exposure-test
  (testing "raw dotenv body flagged; normal HTML clean"
    (let [env "APP_ENV=production\nDB_PASSWORD=hunter2\nSECRET_KEY=abc123\nDEBUG=true\nDB_HOST=localhost\n"]
      (is (= 1 (count (filter #(re-find #"(?i)Dotenv" (str (:title %))) (passive/check-dotenv-exposure {:url "https://h/"} {:body env}))))))
    (is (empty? (filter #(re-find #"(?i)Dotenv" (str (:title %))) (passive/check-dotenv-exposure {:url "https://h/"} {:body "<html>enter your password</html>"}))))
    (is (empty? (filter #(re-find #"(?i)Dotenv" (str (:title %))) (passive/check-dotenv-exposure {:url "https://h/"} {:body "API=1\nMODE=2\n"}))))
    (let [env "APP_ENV=production\nDB_PASSWORD=hunter2\nSECRET_KEY=abc123\nDEBUG=true\nDB_HOST=localhost\n"
          f (first (filter #(re-find #"(?i)Dotenv" (str (:title %))) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body env})))]
      (is (some? f))
      (is (= "40031" (:rule-id f)))
      (is (= "CWE-538" (:cwe f))))))

(deftest check-git-exposure-test
  (testing "git config markers flagged; benign pages clean"
    (is (= 1 (count (filter #(re-find #"(?i)Git repository" (str (:title %))) (passive/check-git-exposure {:url "https://h/"} {:body "ref: refs/heads/main\nrepositoryformatversion = 0\n"})))))
    (is (empty? (filter #(re-find #"(?i)Git repository" (str (:title %))) (passive/check-git-exposure {:url "https://h/"} {:body "<html>hello</html>"}))))
    (is (empty? (filter #(re-find #"(?i)Git repository" (str (:title %))) (passive/check-git-exposure {:url "https://h/"} {:body "the [core] module"}))))
    (let [f (first (filter #(re-find #"(?i)Git repository" (str (:title %))) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "[core]\nrepositoryformatversion = 0\n"})))]
      (is (some? f))
      (is (= "40032" (:rule-id f)))
      (is (= "CWE-538" (:cwe f))))))

(deftest check-backup-exposure-test
  (testing "SQL dump / archive markers flagged; normal pages clean"
    (is (= 1 (count (filter #(re-find #"(?i)Backup/archive" (str (:title %))) (passive/check-backup-exposure {:url "https://h/"} {:body "-- MySQL dump 10.13\nCREATE TABLE users"})))))
    (is (= 1 (count (filter #(re-find #"(?i)Backup/archive" (str (:title %))) (passive/check-backup-exposure {:url "https://h/"} {:body "PK\u0003\u0004 binary"})))))
    (is (empty? (filter #(re-find #"(?i)Backup/archive" (str (:title %))) (passive/check-backup-exposure {:url "https://h/"} {:body "<html>hello</html>"}))))
    (let [f (first (filter #(re-find #"(?i)Backup/archive" (str (:title %))) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "-- MySQL dump 10.13"})))]
      (is (some? f))
      (is (= "40033" (:rule-id f)))
      (is (= "CWE-552" (:cwe f))))))

(deftest check-phpinfo-exposure-test
  (testing "phpinfo markers flagged; benign pages clean"
    (is (= 1 (count (filter #(re-find #"(?i)phpinfo" (str (:title %))) (passive/check-phpinfo-exposure {:url "https://h/"} {:body "phpinfo()\nPHP Version 8.1.2"})))))
    (is (= 1 (count (filter #(re-find #"(?i)phpinfo" (str (:title %))) (passive/check-phpinfo-exposure {:url "https://h/"} {:body "Loaded modules: Core, curl"})))))
    (is (empty? (filter #(re-find #"(?i)phpinfo" (str (:title %))) (passive/check-phpinfo-exposure {:url "https://h/"} {:body "<html>hello</html>"}))))
    (is (empty? (filter #(re-find #"(?i)phpinfo" (str (:title %))) (passive/check-phpinfo-exposure {:url "https://h/"} {:body "PHP Version is documented"}))))
    (let [f (first (filter #(re-find #"(?i)phpinfo" (str (:title %))) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "phpinfo()\nPHP Version 8.1.2"})))]
      (is (some? f))
      (is (= "40034" (:rule-id f)))
      (is (= "CWE-209" (:cwe f))))))

(deftest check-stacktrace-exposure-test
  (testing "stack trace markers flagged; generic pages clean"
    (is (= 1 (count (filter #(re-find #"(?i)Stack trace" (str (:title %))) (passive/check-stacktrace-exposure {:url "https://h/"} {:body "Traceback (most recent call last):\n File \"app.py\", line 1"})))))
    (is (= 1 (count (filter #(re-find #"(?i)Stack trace" (str (:title %))) (passive/check-stacktrace-exposure {:url "https://h/"} {:body "Exception in thread \"main\" java.lang.NullPointerException\n at com.example.App.main(App.java:42)"})))))
    (is (= 1 (count (filter #(re-find #"(?i)Stack trace" (str (:title %))) (passive/check-stacktrace-exposure {:url "https://h/"} {:body "TypeError: Cannot read properties\n at Object.<anonymous> (/app/index.js:10:5)"})))))
    (is (empty? (filter #(re-find #"(?i)Stack trace" (str (:title %))) (passive/check-stacktrace-exposure {:url "https://h/"} {:body "<html>500 Internal Server Error</html>"}))))
    (let [f (first (filter #(re-find #"(?i)Stack trace" (str (:title %))) (passive/passive-scan {:url "https://h/"} {:status 500 :headers {} :body "Traceback (most recent call last):"})))]
      (is (some? f))
      (is (= "40035" (:rule-id f)))
      (is (= "CWE-209" (:cwe f))))))

(deftest check-password-in-url-test
  (testing "password/token param in URL flagged; normal URLs clean"
    (is (= 1 (count (filter #(re-find #"(?i)Sensitive parameter" (str (:title %))) (passive/check-password-in-url {:url "https://h/login?password=hunter2"} {:body ""})))))
    (is (= 1 (count (filter #(re-find #"(?i)Sensitive parameter" (str (:title %))) (passive/check-password-in-url {:url "https://h/api?api_key=abc123"} {:body ""})))))
    (is (empty? (filter #(re-find #"(?i)Sensitive parameter" (str (:title %))) (passive/check-password-in-url {:url "https://h/search?q=hello&page=2"} {:body ""}))))
    (let [f (first (filter #(re-find #"(?i)Sensitive parameter" (str (:title %))) (passive/passive-scan {:url "https://h/?pwd=secret"} {:status 200 :headers {} :body ""})))]
      (is (some? f))
      (is (= "40036" (:rule-id f)))
      (is (= "CWE-359" (:cwe f))))))

(deftest check-url-credentials-test
  (testing "userinfo in URL flagged; normal URLs clean"
    (is (= 1 (count (filter #(re-find #"(?i)Credentials" (str (:title %))) (passive/check-url-credentials {:url "https://user:pass@h/"} {:body ""})))))
    (is (empty? (filter #(re-find #"(?i)Credentials" (str (:title %))) (passive/check-url-credentials {:url "https://h/path@foo"} {:body ""}))))
    (is (empty? (filter #(re-find #"(?i)Credentials" (str (:title %))) (passive/check-url-credentials {:url "https://h/"} {:body ""}))))
    (let [f (first (filter #(re-find #"(?i)Credentials" (str (:title %))) (passive/passive-scan {:url "http://admin:secret@h/"} {:status 200 :headers {} :body ""})))]
      (is (some? f))
      (is (= "40037" (:rule-id f)))
      (is (= "CWE-359" (:cwe f))))))

(deftest check-email-disclosure-test
  (testing "3+ distinct emails flagged; 1-2 clean"
    (is (= 1 (count (filter #(re-find #"(?i)Email addresses" (str (:title %))) (passive/check-email-disclosure {:url "https://h/"} {:body "a@x.co b@x.co c@x.co"})))))
    (is (empty? (filter #(re-find #"(?i)Email addresses" (str (:title %))) (passive/check-email-disclosure {:url "https://h/"} {:body "info@example.com"}))))
    (is (empty? (filter #(re-find #"(?i)Email addresses" (str (:title %))) (passive/check-email-disclosure {:url "https://h/"} {:body "a@x.co b@x.co"}))))
    (let [f (first (filter #(re-find #"(?i)Email addresses" (str (:title %))) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "a@x.co b@x.co c@x.co d@x.co"})))]
      (is (some? f))
      (is (= "40038" (:rule-id f)))
      (is (= "CWE-359" (:cwe f))))))

(deftest check-login-autocomplete-test
  (testing "password field without autocomplete=off flagged; with off clean"
    (is (= 1 (count (filter #(re-find #"(?i)autocomplete" (str (:title %))) (passive/check-login-autocomplete {:url "https://h/"} {:body "<input type=\"password\" name=\"p\">"})))))
    (is (empty? (filter #(re-find #"(?i)autocomplete" (str (:title %))) (passive/check-login-autocomplete {:url "https://h/"} {:body "<input type=\"password\" autocomplete=\"off\">"}))))
    (is (empty? (filter #(re-find #"(?i)autocomplete" (str (:title %))) (passive/check-login-autocomplete {:url "https://h/"} {:body "<input type=\"text\">"}))))
    (let [f (first (filter #(re-find #"(?i)autocomplete" (str (:title %))) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "<form><input type=password></form>"})))]
      (is (some? f))
      (is (= "40039" (:rule-id f)))
      (is (= "CWE-359" (:cwe f))))))

(deftest check-internal-ip-disclosure-test
  (testing "private IPs flagged; public IP clean"
    (is (= 1 (count (filter #(re-find #"(?i)Internal IP" (str (:title %))) (passive/check-internal-ip-disclosure {:url "https://h/"} {:body "db at 192.168.1.10:5432"})))))
    (is (= 1 (count (filter #(re-find #"(?i)Internal IP" (str (:title %))) (passive/check-internal-ip-disclosure {:url "https://h/"} {:body "10.0.0.1"})))))
    (is (= 1 (count (filter #(re-find #"(?i)Internal IP" (str (:title %))) (passive/check-internal-ip-disclosure {:url "https://h/"} {:body "172.16.0.5"})))))
    (is (empty? (filter #(re-find #"(?i)Internal IP" (str (:title %))) (passive/check-internal-ip-disclosure {:url "https://h/"} {:body "8.8.8.8"}))))
    (is (empty? (filter #(re-find #"(?i)Internal IP" (str (:title %))) (passive/check-internal-ip-disclosure {:url "https://h/"} {:body "172.32.0.1"}))))
    (let [f (first (filter #(re-find #"(?i)Internal IP" (str (:title %))) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "upstream 127.0.0.1"})))]
      (is (some? f))
      (is (= "40040" (:rule-id f)))
      (is (= "CWE-200" (:cwe f))))))

(deftest check-internal-hostname-test
  (testing "internal hostnames flagged; public hostnames clean"
    (is (= 1 (count (filter #(re-find #"(?i)Internal hostname" (str (:title %))) (passive/check-internal-hostname {:url "https://h/"} {:body "api.db.internal:5432"})))))
    (is (= 1 (count (filter #(re-find #"(?i)Internal hostname" (str (:title %))) (passive/check-internal-hostname {:url "https://h/"} {:body "printer.local"})))))
    (is (empty? (filter #(re-find #"(?i)Internal hostname" (str (:title %))) (passive/check-internal-hostname {:url "https://h/"} {:body "api.example.com"}))))
    (is (empty? (filter #(re-find #"(?i)Internal hostname" (str (:title %))) (passive/check-internal-hostname {:url "https://h/"} {:body "the local store"}))))
    (let [f (first (filter #(re-find #"(?i)Internal hostname" (str (:title %))) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "cache.intranet"})))]
      (is (some? f))
      (is (= "40041" (:rule-id f)))
      (is (= "CWE-200" (:cwe f))))))

(deftest check-jwt-exposure-test
  (testing "JWT tokens flagged; plain text clean"
    (is (= 1 (count (filter #(re-find #"(?i)JWT" (str (:title %))) (passive/check-jwt-exposure {:url "https://h/"} {:body "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"})))))
    (is (= 1 (count (filter #(re-find #"(?i)JWT" (str (:title %))) (passive/check-jwt-exposure {:url "https://h/?t=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123456"} {:body ""})))))
    (is (empty? (filter #(re-find #"(?i)JWT" (str (:title %))) (passive/check-jwt-exposure {:url "https://h/"} {:body "the token is secret now"}))))
    (let [f (first (filter #(re-find #"(?i)JWT" (str (:title %))) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123456"})))]
      (is (some? f))
      (is (= "40042" (:rule-id f)))
      (is (= "CWE-798" (:cwe f))))))

(deftest check-apikey-exposure-test
  (testing "provider key shapes flagged; normal text clean"
    (is (= 1 (count (filter #(re-find #"(?i)API key" (str (:title %))) (passive/check-apikey-exposure {:url "https://h/"} {:body "key AKIAIOSFODNN7EXAMPLE"})))))
    (is (= 1 (count (filter #(re-find #"(?i)API key" (str (:title %))) (passive/check-apikey-exposure {:url "https://h/"} {:body "AIzaSyA-1234567890abcdefghijklmnopqrstuv"})))))
    (is (= 1 (count (filter #(re-find #"(?i)API key" (str (:title %))) (passive/check-apikey-exposure {:url "https://h/"} {:body "ghp_1234567890abcdefghijklmnopqrstuvwxQRST"})))))
    (is (empty? (filter #(re-find #"(?i)API key" (str (:title %))) (passive/check-apikey-exposure {:url "https://h/"} {:body "the api key is required"}))))
    (let [f (first (filter #(re-find #"(?i)API key" (str (:title %))) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "sk-live-1234567890abcdefghijklmnop"})))]
      (is (some? f))
      (is (= "40043" (:rule-id f)))
      (is (= "CWE-798" (:cwe f))))))

(deftest check-private-key-exposure-test
  (testing "PEM blocks flagged; other text clean"
    (is (= 1 (count (filter #(re-find #"(?i)Private key" (str (:title %))) (passive/check-private-key-exposure {:url "https://h/"} {:body "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."})))))
    (is (= 1 (count (filter #(re-find #"(?i)Private key" (str (:title %))) (passive/check-private-key-exposure {:url "https://h/"} {:body "-----BEGIN PRIVATE KEY-----"})))))
    (is (empty? (filter #(re-find #"(?i)Private key" (str (:title %))) (passive/check-private-key-exposure {:url "https://h/"} {:body "-----BEGIN CERTIFICATE-----"}))))
    (is (empty? (filter #(re-find #"(?i)Private key" (str (:title %))) (passive/check-private-key-exposure {:url "https://h/"} {:body "hello"}))))
    (let [f (first (filter #(re-find #"(?i)Private key" (str (:title %))) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "-----BEGIN OPENSSH PRIVATE KEY-----"})))]
      (is (some? f))
      (is (= "40044" (:rule-id f)))
      (is (= "CWE-798" (:cwe f))))))

(deftest check-cookie-attributes-test
  (testing "cookies missing HttpOnly/Secure flagged; full attrs clean"
    (is (= 1 (count (filter #(re-find #"(?i)Cookie missing" (str (:title %))) (passive/check-cookie-attributes {:url "https://h/"} {:headers {"set-cookie" "sid=abc; Path=/"} :body ""})))))
    (is (= 1 (count (filter #(re-find #"(?i)Cookie missing" (str (:title %))) (passive/check-cookie-attributes {:url "https://h/"} {:headers {"set-cookie" "sid=abc; HttpOnly"} :body ""})))))
    (is (empty? (filter #(re-find #"(?i)Cookie missing" (str (:title %))) (passive/check-cookie-attributes {:url "https://h/"} {:headers {"set-cookie" "sid=abc; Secure; HttpOnly; Path=/"} :body ""}))))
    (is (empty? (filter #(re-find #"(?i)Cookie missing" (str (:title %))) (passive/check-cookie-attributes {:url "https://h/"} {:headers {} :body ""}))))
    (let [f (first (filter #(= "40045" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {"set-cookie" "sid=abc"} :body ""})))]
      (is (some? f))
      (is (= "40045" (:rule-id f)))
      (is (= "CWE-1004" (:cwe f))))))

(deftest check-cookie-samesite-test
  (testing "cookies without SameSite flagged; with SameSite clean"
    (is (= 1 (count (filter #(re-find #"(?i)SameSite" (str (:title %))) (passive/check-cookie-samesite {:url "https://h/"} {:headers {"set-cookie" "sid=abc; Secure; HttpOnly"} :body ""})))))
    (is (empty? (filter #(re-find #"(?i)SameSite" (str (:title %))) (passive/check-cookie-samesite {:url "https://h/"} {:headers {"set-cookie" "sid=abc; SameSite=Lax"} :body ""}))))
    (is (empty? (filter #(re-find #"(?i)SameSite" (str (:title %))) (passive/check-cookie-samesite {:url "https://h/"} {:headers {} :body ""}))))
    (let [f (first (filter #(= "40046" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {"set-cookie" "sid=abc"} :body ""})))]
      (is (some? f))
      (is (= "40046" (:rule-id f)))
      (is (= "CWE-1004" (:cwe f))))))

(deftest check-missing-sri-test
  (testing "external script w/o integrity flagged; local/inline/SRI clean"
    (is (= 1 (count (filter #(re-find #"(?i)Subresource Integrity" (str (:title %))) (passive/check-missing-sri {:url "https://h/"} {:body "<script src=\"https://cdn.example.com/a.js\"></script>"})))))
    (is (empty? (filter #(re-find #"(?i)Subresource Integrity" (str (:title %))) (passive/check-missing-sri {:url "https://h/"} {:body "<script src=\"/assets/app.js\"></script>"}))))
    (is (empty? (filter #(re-find #"(?i)Subresource Integrity" (str (:title %))) (passive/check-missing-sri {:url "https://h/"} {:body "<script src=\"https://cdn.example.com/a.js\" integrity=\"sha384-abc\"></script>"}))))
    (is (empty? (filter #(re-find #"(?i)Subresource Integrity" (str (:title %))) (passive/check-missing-sri {:url "https://h/"} {:body "<script>var x=1;</script>"}))))
    (let [f (first (filter #(= "40047" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "<script src=\"https://cdn.example.com/a.js\"></script>"})))]
      (is (some? f))
      (is (= "40047" (:rule-id f)))
      (is (= "CWE-829" (:cwe f))))))

(deftest check-tabnabbing-test
  (testing "target=_blank w/o noopener flagged; noopener/self clean"
    (is (= 1 (count (filter #(re-find #"(?i)noopener" (str (:title %))) (passive/check-tabnabbing {:url "https://h/"} {:body "<a href=\"https://x\" target=\"_blank\">x</a>"})))))
    (is (empty? (filter #(re-find #"(?i)noopener" (str (:title %))) (passive/check-tabnabbing {:url "https://h/"} {:body "<a href=\"https://x\" target=\"_blank\" rel=\"noopener\">x</a>"}))))
    (is (empty? (filter #(re-find #"(?i)noopener" (str (:title %))) (passive/check-tabnabbing {:url "https://h/"} {:body "<a href=\"/y\">y</a>"}))))
    (let [f (first (filter #(= "40048" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "<a href=\"https://x\" target=\"_blank\">x</a>"})))]
      (is (some? f))
      (is (= "40048" (:rule-id f)))
      (is (= "CWE-1021" (:cwe f))))))

(deftest check-mixed-content-test
  (testing "http refs on https flagged; http pages / https-only clean"
    (is (= 1 (count (filter #(re-find #"(?i)Mixed content" (str (:title %))) (passive/check-mixed-content {:url "https://h/"} {:body "<img src=\"http://cdn.example.com/a.png\">"})))))
    (is (empty? (filter #(re-find #"(?i)Mixed content" (str (:title %))) (passive/check-mixed-content {:url "http://h/"} {:body "<img src=\"http://cdn.example.com/a.png\">"}))))
    (is (empty? (filter #(re-find #"(?i)Mixed content" (str (:title %))) (passive/check-mixed-content {:url "https://h/"} {:body "<img src=\"https://cdn.example.com/a.png\">"}))))
    (let [f (first (filter #(= "40049" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "<a href=\"http://x.example\">x</a>"})))]
      (is (some? f))
      (is (= "40049" (:rule-id f)))
      (is (= "CWE-319" (:cwe f))))))

(deftest check-insecure-websocket-test
  (testing "ws:// on https flagged; wss/http pages clean"
    (is (= 1 (count (filter #(re-find #"(?i)WebSocket" (str (:title %))) (passive/check-insecure-websocket {:url "https://h/"} {:body "new WebSocket(\"ws://chat.example/socket\")"})))))
    (is (empty? (filter #(re-find #"(?i)WebSocket" (str (:title %))) (passive/check-insecure-websocket {:url "https://h/"} {:body "new WebSocket(\"wss://chat.example/socket\")"}))))
    (is (empty? (filter #(re-find #"(?i)WebSocket" (str (:title %))) (passive/check-insecure-websocket {:url "http://h/"} {:body "new WebSocket(\"ws://chat.example/socket\")"}))))
    (let [f (first (filter #(= "40050" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "ws://x.example/sock"})))]
      (is (some? f))
      (is (= "40050" (:rule-id f)))
      (is (= "CWE-319" (:cwe f))))))

(deftest check-cookie-long-expiry-test
  (testing "year 2035+ expiry flagged; near/short clean"
    (is (= 1 (count (filter #(re-find #"(?i)excessive expiry" (str (:title %))) (passive/check-cookie-long-expiry {:url "https://h/"} {:headers {"set-cookie" "sid=abc; Expires=Wed, 01 Jan 2040 00:00:00 GMT"} :body ""})))))
    (is (empty? (filter #(re-find #"(?i)excessive expiry" (str (:title %))) (passive/check-cookie-long-expiry {:url "https://h/"} {:headers {"set-cookie" "sid=abc; Expires=Wed, 01 Jan 2027 00:00:00 GMT"} :body ""}))))
    (is (empty? (filter #(re-find #"(?i)excessive expiry" (str (:title %))) (passive/check-cookie-long-expiry {:url "https://h/"} {:headers {"set-cookie" "sid=abc; Max-Age=3600"} :body ""}))))
    (let [f (first (filter #(= "40051" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {"set-cookie" "sid=abc; Expires=Fri, 01 Jan 2049 00:00:00 GMT"} :body ""})))]
      (is (some? f))
      (is (= "40051" (:rule-id f)))
      (is (= "CWE-1004" (:cwe f))))))

(deftest check-clickjacking-test
  (testing "no XFO/CSP ancestors flagged; either header clean"
    (is (= 1 (count (filter #(re-find #"(?i)clickjacking" (str (:title %))) (passive/check-clickjacking {:url "https://h/"} {:headers {} :body ""})))))
    (is (empty? (filter #(re-find #"(?i)clickjacking" (str (:title %))) (passive/check-clickjacking {:url "https://h/"} {:headers {"x-frame-options" "SAMEORIGIN"} :body ""}))))
    (is (empty? (filter #(re-find #"(?i)clickjacking" (str (:title %))) (passive/check-clickjacking {:url "https://h/"} {:headers {"content-security-policy" "frame-ancestors 'self'"} :body ""}))))
    (let [f (first (filter #(= "40052" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body ""})))]
      (is (some? f))
      (is (= "40052" (:rule-id f)))
      (is (= "CWE-1021" (:cwe f))))))

(deftest check-hsts-test
  (testing "https w/o HSTS flagged; HSTS present / http clean"
    (is (= 1 (count (filter #(re-find #"(?i)Strict-Transport" (str (:title %))) (passive/check-hsts {:url "https://h/"} {:headers {} :body ""})))))
    (is (empty? (filter #(re-find #"(?i)Strict-Transport" (str (:title %))) (passive/check-hsts {:url "https://h/"} {:headers {"strict-transport-security" "max-age=31536000; includeSubDomains"} :body ""}))))
    (is (empty? (filter #(re-find #"(?i)Strict-Transport" (str (:title %))) (passive/check-hsts {:url "http://h/"} {:headers {} :body ""}))))
    (let [f (first (filter #(= "40053" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body ""})))]
      (is (some? f))
      (is (= "40053" (:rule-id f)))
      (is (= "CWE-319" (:cwe f))))))

(deftest check-nosniff-test
  (testing "missing/non-nosniff flagged; nosniff clean"
    (is (= 1 (count (filter #(re-find #"(?i)nosniff" (str (:title %))) (passive/check-nosniff {:url "https://h/"} {:headers {} :body ""})))))
    (is (= 1 (count (filter #(re-find #"(?i)nosniff" (str (:title %))) (passive/check-nosniff {:url "https://h/"} {:headers {"x-content-type-options" "sameorigin"} :body ""})))))
    (is (empty? (filter #(re-find #"(?i)nosniff" (str (:title %))) (passive/check-nosniff {:url "https://h/"} {:headers {"x-content-type-options" "nosniff"} :body ""}))))
    (let [f (first (filter #(= "40054" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body ""})))]
      (is (some? f))
      (is (= "40054" (:rule-id f)))
      (is (= "CWE-693" (:cwe f))))))

(deftest check-referrer-policy-test
  (testing "missing flagged; present clean"
    (is (= 1 (count (filter #(re-find #"(?i)Referrer-Policy" (str (:title %))) (passive/check-referrer-policy {:url "https://h/"} {:headers {} :body ""})))))
    (is (empty? (filter #(re-find #"(?i)Referrer-Policy" (str (:title %))) (passive/check-referrer-policy {:url "https://h/"} {:headers {"referrer-policy" "no-referrer"} :body ""}))))
    (let [f (first (filter #(= "40055" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body ""})))]
      (is (some? f))
      (is (= "40055" (:rule-id f)))
      (is (= "CWE-693" (:cwe f))))))

(deftest check-permissions-policy-test
  (testing "missing flagged; present clean"
    (is (= 1 (count (filter #(re-find #"(?i)Permissions-Policy" (str (:title %))) (passive/check-permissions-policy {:url "https://h/"} {:headers {} :body ""})))))
    (is (empty? (filter #(re-find #"(?i)Permissions-Policy" (str (:title %))) (passive/check-permissions-policy {:url "https://h/"} {:headers {"permissions-policy" "camera=(), microphone=()"} :body ""}))))
    (let [f (first (filter #(= "40056" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body ""})))]
      (is (some? f))
      (is (= "40056" (:rule-id f)))
      (is (= "CWE-693" (:cwe f))))))

(deftest check-http-redirect-test
  (testing "http refresh on https flagged; https/http-page clean"
    (is (= 1 (count (filter #(re-find #"(?i)HTTP redirect" (str (:title %))) (passive/check-http-redirect {:url "https://h/"} {:body "<meta http-equiv=\"refresh\" content=\"0;url=http://x.example/\">"})))))
    (is (empty? (filter #(re-find #"(?i)HTTP redirect" (str (:title %))) (passive/check-http-redirect {:url "https://h/"} {:body "<meta http-equiv=\"refresh\" content=\"0;url=https://x.example/\">"}))))
    (is (empty? (filter #(re-find #"(?i)HTTP redirect" (str (:title %))) (passive/check-http-redirect {:url "http://h/"} {:body "<meta http-equiv=\"refresh\" content=\"0;url=http://x.example/\">"}))))
    (let [f (first (filter #(= "40057" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "<meta http-equiv=\"refresh\" content=\"0;url=http://x.example/\">"})))]
      (is (some? f))
      (is (= "40057" (:rule-id f)))
      (is (= "CWE-319" (:cwe f))))))

(deftest check-csp-unsafe-inline-test
  (testing "unsafe-inline flagged; strict/absent clean"
    (is (= 1 (count (filter #(re-find #"(?i)unsafe-inline" (str (:title %))) (passive/check-csp-unsafe-inline {:url "https://h/"} {:headers {"content-security-policy" "script-src 'unsafe-inline'"} :body ""})))))
    (is (empty? (filter #(re-find #"(?i)unsafe-inline" (str (:title %))) (passive/check-csp-unsafe-inline {:url "https://h/"} {:headers {"content-security-policy" "default-src 'self'"} :body ""}))))
    (is (empty? (filter #(re-find #"(?i)unsafe-inline" (str (:title %))) (passive/check-csp-unsafe-inline {:url "https://h/"} {:headers {} :body ""}))))
    (let [f (first (filter #(= "40058" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {"content-security-policy" "style-src 'unsafe-inline'"} :body ""})))]
      (is (some? f))
      (is (= "40058" (:rule-id f)))
      (is (= "CWE-693" (:cwe f))))))

(deftest check-csp-missing-test
  (testing "no CSP flagged; CSP/report-only clean"
    (is (= 1 (count (filter #(re-find #"(?i)Missing Content-Security" (str (:title %))) (passive/check-csp-missing {:url "https://h/"} {:headers {} :body ""})))))
    (is (empty? (filter #(re-find #"(?i)Missing Content-Security" (str (:title %))) (passive/check-csp-missing {:url "https://h/"} {:headers {"content-security-policy" "default-src 'self'"} :body ""}))))
    (is (empty? (filter #(re-find #"(?i)Missing Content-Security" (str (:title %))) (passive/check-csp-missing {:url "https://h/"} {:headers {"content-security-policy-report-only" "default-src 'self'"} :body ""}))))
    (let [f (first (filter #(= "40059" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body ""})))]
      (is (some? f))
      (is (= "40059" (:rule-id f)))
      (is (= "CWE-693" (:cwe f))))))

(deftest check-form-http-action-test
  (testing "http form action on https flagged; https/http-page clean"
    (is (= 1 (count (filter #(re-find #"(?i)Form submits" (str (:title %))) (passive/check-form-http-action {:url "https://h/"} {:body "<form action=\"http://x.example/login\" method=\"post\">"})))))
    (is (empty? (filter #(re-find #"(?i)Form submits" (str (:title %))) (passive/check-form-http-action {:url "https://h/"} {:body "<form action=\"https://x.example/login\" method=\"post\">"}))))
    (is (empty? (filter #(re-find #"(?i)Form submits" (str (:title %))) (passive/check-form-http-action {:url "http://h/"} {:body "<form action=\"http://x.example/login\">"}))))
    (let [f (first (filter #(= "40060" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "<form action=\"http://x.example/login\">"})))]
      (is (some? f))
      (is (= "40060" (:rule-id f)))
      (is (= "CWE-319" (:cwe f))))))

(deftest check-dom-open-redirect-test
  (testing "location.hash redirect flagged; static/allowlist clean"
    (is (= 1 (count (filter #(re-find #"(?i)open redirect" (str (:title %))) (passive/check-dom-open-redirect {:url "https://h/"} {:body "location.href = location.hash"})))))
    (is (empty? (filter #(re-find #"(?i)open redirect" (str (:title %))) (passive/check-dom-open-redirect {:url "https://h/"} {:body "location.href = \"/home\""}))))
    (is (empty? (filter #(re-find #"(?i)open redirect" (str (:title %))) (passive/check-dom-open-redirect {:url "https://h/"} {:body "var next = \"/ok\"; if(next.startsWith(\"/\")) location.href = next;"}))))
    (let [f (first (filter #(= "40061" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "location.assign(location.search)"})))]
      (is (some? f))
      (is (= "40061" (:rule-id f)))
      (is (= "CWE-601" (:cwe f))))))

(deftest check-postmessage-wildcard-test
  (testing "wildcard targetOrigin flagged; explicit clean"
    (is (= 1 (count (filter #(re-find #"(?i)postMessage" (str (:title %))) (passive/check-postmessage-wildcard {:url "https://h/"} {:body "w.postMessage({t:1}, \"*\")"})))))
    (is (empty? (filter #(re-find #"(?i)postMessage" (str (:title %))) (passive/check-postmessage-wildcard {:url "https://h/"} {:body "w.postMessage({t:1}, \"https://app.example\")"}))))
    (is (empty? (filter #(re-find #"(?i)postMessage" (str (:title %))) (passive/check-postmessage-wildcard {:url "https://h/"} {:body "window.addEventListener(\"message\", handler);"}))))
    (let [f (first (filter #(= "40062" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "iframe.contentWindow.postMessage(data, '*')"})))]
      (is (some? f))
      (is (= "40062" (:rule-id f)))
      (is (= "CWE-79" (:cwe f))))))


(deftest check-viewport-zoom-test
  (testing "maximum-scale/user-scalable flagged; default clean"
    (is (= 1 (count (filter #(re-find #"(?i)zoom" (str (:title %))) (passive/check-viewport-zoom {:url "https://h/"} {:body "<meta name=\"viewport\" content=\"width=device-width, maximum-scale=1\">"})))))
    (is (= 1 (count (filter #(re-find #"(?i)zoom" (str (:title %))) (passive/check-viewport-zoom {:url "https://h/"} {:body "<meta name=\"viewport\" content=\"width=device-width, user-scalable=no\">"})))))
    (is (empty? (filter #(re-find #"(?i)zoom" (str (:title %))) (passive/check-viewport-zoom {:url "https://h/"} {:body "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"}))))
    (let [f (first (filter #(= "40063" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "<meta content=\"maximum-scale=1\">"})))]
      (is (some? f))
      (is (= "40063" (:rule-id f)))
      (is (= "CWE-693" (:cwe f))))))

(deftest union-probe-test
  (testing "union probe helpers: params, evidence, scan"
    (is (= "' UNION SELECT 1--" (get (active/union-probe-params "q") "q")))
    (is (nil? (active/union-evidence "hello" "hello")))
    (is (some? (active/union-evidence "hello" "UNIONMARKER echoed")))
    (let [f (active/union-sqli-scan {:url "https://h/s.php" :param-name "q"
                                      :send-fn (fn [_] {:status 200 :body "UNIONMARKER"})
                                      :baseline-body "hello"})]
      (is (some? f))
      (is (= 40013 (:rule-id f)))
      (is (= "CWE-89" (:cwe f))))
    (let [f (active/union-sqli-scan {:url "https://h/s.php" :param-name "q"
                                      :send-fn (fn [_] {:status 200 :body "no marker"})
                                      :baseline-body "hello"})]
      (is (nil? f)))))

(deftest error-sqli-evidence-test
  (testing "db signature yields evidence; clean body yields nil"
    (is (some? (active/error-sqli-evidence "You have an error in your SQL syntax; check the manual")))
    (is (some? (active/error-sqli-evidence "SQLSTATE[HY000] error")))
    (is (some? (active/error-sqli-evidence "ORA-00933: SQL command not properly ended")))
    (is (nil? (active/error-sqli-evidence "hello world")))))

(deftest reflection-evidence-test
  (testing "marker reflection yields evidence; absent yields nil"
    (is (some? (active/reflection-evidence "<div>zz9marker</div>" "zz9marker")))
    (is (nil? (active/reflection-evidence "<div>hello</div>" "zz9marker")))
    (is (nil? (active/reflection-evidence "<div>zz9marker</div>" nil)))))

(deftest xss-reflection-scan-test
  (testing "xss reflection scan: reflected marker yields finding"
    (let [f (active/xss-reflection-scan {:url "https://h/q.php" :param-name "q"
                                          :send-fn (fn [_] {:status 200 :body "<div>zz9marker</div>"})})]
      (is (some? f))
      (is (= 40012 (:rule-id f)))
      (is (= "CWE-79" (:cwe f))))
    (let [f (active/xss-reflection-scan {:url "https://h/q.php" :param-name "q"
                                          :send-fn (fn [_] {:status 200 :body "no reflection"})})]
      (is (nil? f)))))

(deftest ssti-scan-test
  (testing "ssti probe: evaluation 49 yields finding"
    (let [f (active/ssti-scan {:url "https://h/t.php" :param-name "q"
                                :send-fn (fn [_] {:status 200 :body "result: 49"})
                                :baseline-body "hello"})]
      (is (some? f))
      (is (= 40029 (:rule-id f)))
      (is (= "CWE-94" (:cwe f))))
    (let [f (active/ssti-scan {:url "https://h/t.php" :param-name "q"
                                :send-fn (fn [_] {:status 200 :body "no eval"})
                                :baseline-body "hello"})]
      (is (nil? f)))))

(deftest traversal-scan-test
  (testing "traversal probe: marker listed yields finding"
    (let [f (active/traversal-scan {:url "https://h/f.php" :send-fn (fn [_] {:status 200 :body "zz9traversal"})})]
      (is (some? f))
      (is (= 40066 (:rule-id f)))
      (is (= "CWE-22" (:cwe f))))
    (let [f (active/traversal-scan {:url "https://h/f.php" :send-fn (fn [_] {:status 404 :body "not found"})})]
      (is (nil? f)))))

(deftest xxe-scan-test
  (testing "xxe probe: entity expansion yields finding"
    (let [f (active/xxe-scan {:url "https://h/x.php"
                               :send-fn (fn [_] {:status 200 :body "<x>zz9xxe</x>"})
                               :baseline-body "hello"})]
      (is (some? f))
      (is (= 40067 (:rule-id f)))
      (is (= "CWE-611" (:cwe f))))
    (let [f (active/xxe-scan {:url "https://h/x.php"
                               :send-fn (fn [_] {:status 200 :body "rejected"})
                               :baseline-body "hello"})]
      (is (nil? f)))))

(deftest cmdi-scan-test
  (testing "cmdi probe: echo marker yields finding"
    (let [f (active/cmdi-scan {:url "https://h/c.php" :param-name "q"
                                :send-fn (fn [_] {:status 200 :body "zz9cmdi"})
                                :baseline-body "hello"})]
      (is (some? f))
      (is (= 40068 (:rule-id f)))
      (is (= "CWE-78" (:cwe f))))
    (let [f (active/cmdi-scan {:url "https://h/c.php" :param-name "q"
                                :send-fn (fn [_] {:status 200 :body "clean"})
                                :baseline-body "hello"})]
      (is (nil? f)))))

(deftest open-redirect-scan-test
  (testing "open redirect probe: off-site location yields finding"
    (let [f (active/open-redirect-scan {:url "https://h/r.php" :param-name "next"
                                         :send-fn (fn [_] {:status 302 :headers {"Location" "//evil.example/path"} :body ""})})]
      (is (some? f))
      (is (= 40069 (:rule-id f)))
      (is (= "CWE-601" (:cwe f))))
    (let [f (active/open-redirect-scan {:url "https://h/r.php" :param-name "next"
                                         :send-fn (fn [_] {:status 200 :headers {} :body "ok"})})]
      (is (nil? f)))))

(deftest ldap-scan-test
  (testing "ldap probe: inflated response yields finding"
    (let [f (active/ldap-scan {:url "https://h/l.php" :param-name "q"
                                :send-fn (fn [_] {:status 200 :body (apply str (repeat 500 "x"))})
                                :baseline-body "hello"})]
      (is (some? f))
      (is (= 40070 (:rule-id f)))
      (is (= "CWE-90" (:cwe f))))
    (let [f (active/ldap-scan {:url "https://h/l.php" :param-name "q"
                                :send-fn (fn [_] {:status 200 :body "small"})
                                :baseline-body "hello"})]
      (is (nil? f)))))

(deftest crlf-scan-test
  (testing "crlf probe: reflected header yields finding"
    (let [f (active/crlf-scan {:url "https://h/c.php" :param-name "q"
                                :send-fn (fn [_] {:status 200 :headers {"X-Zz9-Probe" "zz9crlf"} :body ""})})]
      (is (some? f))
      (is (= 40071 (:rule-id f)))
      (is (= "CWE-113" (:cwe f))))
    (let [f (active/crlf-scan {:url "https://h/c.php" :param-name "q"
                                :send-fn (fn [_] {:status 200 :headers {} :body ""})})]
      (is (nil? f)))))

(deftest check-deserialization-hint-test
  (testing "serialized markers flagged; benign clean"
    (is (= 1 (count (filter #(re-find #"(?i)Serialized" (str (:title %))) (passive/check-deserialization-hint {:url "https://h/"} {:body "O:8:\"stdClass\":0:{}"})))))
    (is (= 1 (count (filter #(re-find #"(?i)Serialized" (str (:title %))) (passive/check-deserialization-hint {:url "https://h/"} {:body "rO0AB"})))))
    (is (empty? (filter #(re-find #"(?i)Serialized" (str (:title %))) (passive/check-deserialization-hint {:url "https://h/"} {:body "hello world"}))))
    (let [f (first (filter #(= "40072" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "ACED0005"})))]
      (is (some? f))
      (is (= "40072" (:rule-id f)))
      (is (= "CWE-502" (:cwe f))))))

(deftest check-meta-refresh-http-test
  (testing "http refresh flagged; https clean"
    (is (= 1 (count (filter #(re-find #"(?i)Meta refresh" (str (:title %))) (passive/check-meta-refresh-http {:url "https://h/"} {:body "<meta http-equiv=\"refresh\" content=\"0;url=http://example.com/\">"})))))
    (is (empty? (filter #(re-find #"(?i)Meta refresh" (str (:title %))) (passive/check-meta-refresh-http {:url "https://h/"} {:body "<meta http-equiv=\"refresh\" content=\"0;url=https://example.com/\">"}))))
    (let [f (first (filter #(= "40073" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "<meta http-equiv=\"refresh\" content=\"0;url=http://x/\">"})))]
      (is (some? f))
      (is (= "40073" (:rule-id f)))
      (is (= "CWE-319" (:cwe f))))))

(deftest check-content-type-charset-test
  (testing "text charset missing flagged; charset present clean"
    (is (= 1 (count (filter #(re-find #"(?i)charset" (str (:title %))) (passive/check-content-type-charset {:url "https://h/"} {:headers {"Content-Type" "text/html"} :body ""})))))
    (is (empty? (filter #(re-find #"(?i)charset" (str (:title %))) (passive/check-content-type-charset {:url "https://h/"} {:headers {"Content-Type" "text/html; charset=UTF-8"} :body ""}))))
    (is (empty? (filter #(re-find #"(?i)charset" (str (:title %))) (passive/check-content-type-charset {:url "https://h/"} {:headers {"Content-Type" "image/png"} :body ""}))))
    (let [f (first (filter #(= "40074" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {"Content-Type" "text/plain"} :body "x"})))]
      (is (some? f))
      (is (= "40074" (:rule-id f)))
      (is (= "CWE-116" (:cwe f))))))

(deftest check-allow-methods-test
  (testing "TRACE/CONNECT flagged; standard methods clean"
    (is (= 1 (count (filter #(re-find #"(?i)methods" (str (:title %))) (passive/check-allow-methods {:url "https://h/"} {:headers {"Access-Control-Allow-Methods" "GET, POST, TRACE"} :body ""})))))
    (is (= 1 (count (filter #(re-find #"(?i)methods" (str (:title %))) (passive/check-allow-methods {:url "https://h/"} {:headers {"access-control-allow-methods" "GET, CONNECT"} :body ""})))))
    (is (empty? (filter #(re-find #"(?i)methods" (str (:title %))) (passive/check-allow-methods {:url "https://h/"} {:headers {"Access-Control-Allow-Methods" "GET, POST, PUT"} :body ""}))))
    (let [f (first (filter #(= "40075" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {"Access-Control-Allow-Methods" "GET, TRACE"} :body ""})))]
      (is (some? f))
      (is (= "40075" (:rule-id f)))
      (is (= "CWE-16" (:cwe f))))))

(deftest check-server-status-exposure-test
  (testing "status page flagged; normal page clean"
    (is (= 1 (count (filter #(re-find #"(?i)status" (str (:title %))) (passive/check-server-status-exposure {:url "https://h/"} {:body "<h1>Apache Status</h1>"})))))
    (is (empty? (filter #(re-find #"(?i)status" (str (:title %))) (passive/check-server-status-exposure {:url "https://h/"} {:body "<h1>Welcome</h1>"}))))
    (let [f (first (filter #(= "40076" (:rule-id %)) (passive/passive-scan {:url "https://h/server-status"} {:status 200 :headers {} :body "NGINX status"})))]
      (is (some? f))
      (is (= "40076" (:rule-id f)))
      (is (= "CWE-209" (:cwe f))))))

(deftest check-db-backup-exposure-test
  (testing "backup filename flagged; clean body fine"
    (is (= 1 (count (filter #(re-find #"(?i)backup" (str (:title %))) (passive/check-db-backup-exposure {:url "https://h/"} {:body "download db.sql now"})))))
    (is (= 1 (count (filter #(re-find #"(?i)backup" (str (:title %))) (passive/check-db-backup-exposure {:url "https://h/"} {:body "archive.tar.gz"})))))
    (is (empty? (filter #(re-find #"(?i)backup" (str (:title %))) (passive/check-db-backup-exposure {:url "https://h/"} {:body "hello world"}))))
    (let [f (first (filter #(= "40077" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "backup.sql"})))]
      (is (some? f))
      (is (= "40077" (:rule-id f)))
      (is (= "CWE-552" (:cwe f))))))

(deftest check-verbose-error-test
  (testing "path disclosure flagged; generic bodies clean"
    (is (= 1 (count (filter #(re-find #"(?i)verbose" (str (:title %))) (passive/check-verbose-error {:url "https://h/"} {:body "Warning: fopen(/var/www/app.php): failed to open stream"})))))
    (is (= 1 (count (filter #(re-find #"(?i)verbose" (str (:title %))) (passive/check-verbose-error {:url "https://h/"} {:body "Uncaught Error in /home/user/index.php on line 10"})))))
    (is (empty? (filter #(re-find #"(?i)verbose" (str (:title %))) (passive/check-verbose-error {:url "https://h/"} {:body "An error occurred"}))))
    (let [f (first (filter #(= "40078" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 500 :headers {} :body "Notice: x in /etc/passwd"})))]
      (is (some? f))
      (is (= "40078" (:rule-id f)))
      (is (= "CWE-209" (:cwe f))))))

(deftest check-changelog-exposure-test
  (testing "changelog url flagged; other paths clean"
    (is (= 1 (count (filter #(re-find #"(?i)Changelog" (str (:title %))) (passive/check-changelog-exposure {:url "https://h/CHANGELOG.md"} {})))))
    (is (= 1 (count (filter #(re-find #"(?i)Changelog" (str (:title %))) (passive/check-changelog-exposure {:url "https://h/HISTORY.txt"} {})))))
    (is (empty? (passive/check-changelog-exposure {:url "https://h/index.html"} {:status 200 :headers {} :body "ok"})))
    (let [f (first (filter #(= "40079" (:rule-id %)) (passive/passive-scan {:url "https://h/CHANGELOG"} {:status 200 :headers {} :body ""})))]
      (is (some? f))
      (is (= "40079" (:rule-id f)))
      (is (= "CWE-552" (:cwe f))))))

(deftest check-swagger-exposure-test
  (testing "swagger markers flagged; clean body fine"
    (is (= 1 (count (filter #(re-find #"(?i)Swagger" (str (:title %))) (passive/check-swagger-exposure {:url "https://h/"} {:body "<div id=\"swagger-ui\"></div>"})))))
    (is (= 1 (count (filter #(re-find #"(?i)Swagger" (str (:title %))) (passive/check-swagger-exposure {:url "https://h/"} {:body "openapi: 3.0.0"})))))
    (is (empty? (filter #(re-find #"(?i)Swagger" (str (:title %))) (passive/check-swagger-exposure {:url "https://h/"} {:body "hello world"}))))
    (let [f (first (filter #(= "40080" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "swaggerJson"})))]
      (is (some? f))
      (is (= "40080" (:rule-id f)))
      (is (= "CWE-200" (:cwe f))))))

(deftest check-old-jquery-test
  (testing "old jquery flagged; modern clean"
    (is (= 1 (count (filter #(re-find #"(?i)jQuery" (str (:title %))) (passive/check-old-jquery {:url "https://h/"} {:body "<script src=\"jquery-1.12.4.min.js\"></script>"})))))
    (is (= 1 (count (filter #(re-find #"(?i)jQuery" (str (:title %))) (passive/check-old-jquery {:url "https://h/"} {:body "jquery-2.2.4"})))))
    (is (empty? (filter #(re-find #"(?i)jQuery" (str (:title %))) (passive/check-old-jquery {:url "https://h/"} {:body "jquery-3.7.1.min.js"}))))
    (let [f (first (filter #(= "40081" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "jquery-1.11.0"})))]
      (is (some? f))
      (is (= "40081" (:rule-id f)))
      (is (= "CWE-1104" (:cwe f))))))

(deftest check-aws-key-in-body-test
  (testing "AWS key flagged with masked evidence; clean body fine"
    (let [fs (passive/check-aws-key-in-body {:url "https://h/"} {:body "key AKIAIOSFODNN7EXAMPLE end"})]
      (is (= 1 (count fs)))
      (is (re-find #"AKIAIOSF" (str (:evidence (first fs))))))
    (is (empty? (passive/check-aws-key-in-body {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40082" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "AKIAIOSFODNN7EXAMPLE"})))]
      (is (some? f))
      (is (= "40082" (:rule-id f)))
      (is (= "CWE-798" (:cwe f))))))

(deftest check-private-key-in-body-test
  (testing "PEM key flagged; clean body fine"
    (is (= 1 (count (passive/check-private-key-in-body {:url "https://h/"} {:body "-----BEGIN PRIVATE KEY----- rest"}))))
    (is (= 1 (count (passive/check-private-key-in-body {:url "https://h/"} {:body "-----BEGIN RSA PRIVATE KEY-----"}))))
    (is (empty? (passive/check-private-key-in-body {:url "https://h/"} {:body "cert here"})))
    (let [f (first (filter #(= "40083" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "-----BEGIN EC PRIVATE KEY-----"})))]
      (is (some? f))
      (is (= "40083" (:rule-id f)))
      (is (= "CWE-798" (:cwe f))))))

(deftest check-jwt-in-body-test
  (testing "jwt-shaped token flagged; plain body fine"
    (let [jwt "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"]
      (is (= 1 (count (passive/check-jwt-in-body {:url "https://h/"} {:body (str "token: " jwt)}))))
      (is (empty? (passive/check-jwt-in-body {:url "https://h/"} {:body "no token here"})))
      (let [f (first (filter #(= "40084" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body jwt})))]
        (is (some? f))
        (is (= "40084" (:rule-id f)))
        (is (= "CWE-200" (:cwe f)))))))

(deftest check-env-leak-test
  (testing ".env line flagged; clean body fine"
    (is (= 1 (count (passive/check-env-leak {:url "https://h/"} {:body "DB_PASSWORD=secret123\nOTHER=1"}))))
    (is (= 1 (count (passive/check-env-leak {:url "https://h/"} {:body "SECRET_KEY=abc123"}))))
    (is (empty? (passive/check-env-leak {:url "https://h/"} {:body "page text"})))
    (let [f (first (filter #(= "40085" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "API_KEY=xyz"})))]
      (is (some? f))
      (is (= "40085" (:rule-id f)))
      (is (= "CWE-552" (:cwe f))))))

(deftest check-graphql-exposure-test
  (testing "graphql markers flagged; clean body fine"
    (is (= 1 (count (filter #(re-find #"(?i)GraphQL" (str (:title %))) (passive/check-graphql-exposure {:url "https://h/"} {:body "graphql endpoint"})))))
    (is (= 1 (count (filter #(re-find #"(?i)GraphQL" (str (:title %))) (passive/check-graphql-exposure {:url "https://h/"} {:body "__typename"})))))
    (is (empty? (passive/check-graphql-exposure {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40086" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "introspection enabled"})))]
      (is (some? f))
      (is (= "40086" (:rule-id f)))
      (is (= "CWE-200" (:cwe f))))))

(deftest check-actuator-exposure-test
  (testing "actuator links flagged; clean body fine"
    (is (= 1 (count (passive/check-actuator-exposure {:url "https://h/"} {:body "<a href=\"/actuator\">actuator</a>"}))))
    (is (= 1 (count (passive/check-actuator-exposure {:url "https://h/"} {:body "\"_links\":[]"}))))
    (is (empty? (passive/check-actuator-exposure {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40087" (:rule-id %)) (passive/passive-scan {:url "https://h/actuator"} {:status 200 :headers {} :body "/actuator/health"})))]
      (is (some? f))
      (is (= "40087" (:rule-id f)))
      (is (= "CWE-200" (:cwe f))))))

(deftest check-docker-exposure-test
  (testing "docker api markers flagged; clean body fine"
    (is (= 1 (count (passive/check-docker-exposure {:url "https://h/"} {:body "Server: Docker/24.0"}))))
    (is (= 1 (count (passive/check-docker-exposure {:url "https://h/"} {:body "containerd/1.7.0"}))))
    (is (empty? (passive/check-docker-exposure {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40088" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "Docker/25.0.0"})))]
      (is (some? f))
      (is (= "40088" (:rule-id f)))
      (is (= "CWE-200" (:cwe f))))))

(deftest check-svn-exposure-test
  (testing ".svn path flagged; normal url clean"
    (is (= 1 (count (passive/check-svn-exposure {:url "https://h/.svn/entries"} {}))))
    (is (= 1 (count (passive/check-svn-exposure {:url "https://h/app/.svn/wc.db"} {}))))
    (is (empty? (passive/check-svn-exposure {:url "https://h/index.html"} {:status 200 :headers {} :body "ok"})))
    (let [f (first (filter #(= "40089" (:rule-id %)) (passive/passive-scan {:url "https://h/.svn/entries"} {:status 200 :headers {} :body ""})))]
      (is (some? f))
      (is (= "40089" (:rule-id f)))
      (is (= "CWE-552" (:cwe f))))))

(deftest check-git-head-exposure-test
  (testing ".git/HEAD path flagged; normal url clean"
    (is (= 1 (count (passive/check-git-head-exposure {:url "https://h/.git/HEAD"} {}))))
    (is (= 1 (count (passive/check-git-head-exposure {:url "https://h/app/.git/HEAD"} {}))))
    (is (empty? (passive/check-git-head-exposure {:url "https://h/index.html"} {:status 200 :headers {} :body "ok"})))
    (let [f (first (filter #(= "40090" (:rule-id %)) (passive/passive-scan {:url "https://h/.git/HEAD"} {:status 200 :headers {} :body ""})))]
      (is (some? f))
      (is (= "40090" (:rule-id f)))
      (is (= "CWE-552" (:cwe f))))))



(deftest check-ssh-banner-exposure-test
  (testing "ssh banner flagged; clean body fine"
    (is (= 1 (count (passive/check-ssh-banner-exposure {:url "https://h/"} {:body "SSH-2.0-OpenSSH_8.9"}))))
    (is (= 1 (count (passive/check-ssh-banner-exposure {:url "https://h/"} {:body "SSH-1.5-OpenSSH_7.4"}))))
    (is (empty? (passive/check-ssh-banner-exposure {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40092" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "SSH-2.0-OpenSSH_9.3"})))]
      (is (some? f))
      (is (= "40092" (:rule-id f)))
      (is (= "CWE-209" (:cwe f))))))

(deftest check-smtp-banner-exposure-test
  (testing "smtp banner flagged; clean body fine"
    (is (= 1 (count (passive/check-smtp-banner-exposure {:url "https://h/"} {:body "220 mail.example.com ESMTP Postfix"}))))
    (is (= 1 (count (passive/check-smtp-banner-exposure {:url "https://h/"} {:body "220 mx.example.net ESMTP Sendmail"}))))
    (is (empty? (passive/check-smtp-banner-exposure {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40093" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "220 mail.example.com ESMTP"})))]
      (is (some? f))
      (is (= "40093" (:rule-id f)))
      (is (= "CWE-209" (:cwe f))))))

(deftest check-ftp-banner-exposure-test
  (testing "ftp banner flagged; clean body fine"
    (is (= 1 (count (passive/check-ftp-banner-exposure {:url "https://h/"} {:body "220-FileZilla FTP Server"}))))
    (is (= 1 (count (passive/check-ftp-banner-exposure {:url "https://h/"} {:body "220 FTP service ready"}))))
    (is (empty? (passive/check-ftp-banner-exposure {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40094" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "220 FTP"})))]
      (is (some? f))
      (is (= "40094" (:rule-id f)))
      (is (= "CWE-209" (:cwe f))))))

(deftest check-mysql-banner-exposure-test
  (testing "mysql banner flagged; clean body fine"
    (is (= 1 (count (passive/check-mysql-banner-exposure {:url "https://h/"} {:body "5.7.40-MySQL"}))))
    (is (= 1 (count (passive/check-mysql-banner-exposure {:url "https://h/"} {:body "MySQL 8.0.36"}))))
    (is (empty? (passive/check-mysql-banner-exposure {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40095" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "5.7.40-MySQL"})))]
      (is (some? f))
      (is (= "40095" (:rule-id f)))
      (is (= "CWE-209" (:cwe f))))))

(deftest check-pg-banner-exposure-test
  (testing "postgres banner flagged; clean body fine"
    (is (= 1 (count (passive/check-pg-banner-exposure {:url "https://h/"} {:body "PostgreSQL 15.4 on x86_64"}))))
    (is (= 1 (count (passive/check-pg-banner-exposure {:url "https://h/"} {:body "PostgreSQL 9.6"}))))
    (is (empty? (passive/check-pg-banner-exposure {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40096" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "PostgreSQL 14.1"})))]
      (is (some? f))
      (is (= "40096" (:rule-id f)))
      (is (= "CWE-209" (:cwe f))))))

(deftest check-redis-banner-exposure-test
  (testing "redis banner flagged; clean body fine"
    (is (= 1 (count (passive/check-redis-banner-exposure {:url "https://h/"} {:body "redis_version:7.2.0"}))))
    (is (= 1 (count (passive/check-redis-banner-exposure {:url "https://h/"} {:body "redis_version"}))))
    (is (empty? (passive/check-redis-banner-exposure {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40097" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "redis_version"})))]
      (is (some? f))
      (is (= "40097" (:rule-id f)))
      (is (= "CWE-209" (:cwe f))))))

(deftest check-mongo-banner-exposure-test
  (testing "mongo banner flagged; clean body fine"
    (is (= 1 (count (passive/check-mongo-banner-exposure {:url "https://h/"} {:body "MongoDB server version: 7.0.5"}))))
    (is (= 1 (count (passive/check-mongo-banner-exposure {:url "https://h/"} {:body "MongoDB server version"}))))
    (is (empty? (passive/check-mongo-banner-exposure {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40098" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "MongoDB server version: 6.0"})))]
      (is (some? f))
      (is (= "40098" (:rule-id f)))
      (is (= "CWE-209" (:cwe f))))))

(deftest check-es-banner-exposure-test
  (testing "es banner flagged; clean body fine"
    (is (= 1 (count (passive/check-es-banner-exposure {:url "https://h/"} {:body "{\"cluster_name\":\"es-cluster\"}"}))))
    (is (= 1 (count (passive/check-es-banner-exposure {:url "https://h/"} {:body "elasticsearch cluster"}))))
    (is (empty? (passive/check-es-banner-exposure {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40099" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "cluster_name"})))]
      (is (some? f))
      (is (= "40099" (:rule-id f)))
      (is (= "CWE-209" (:cwe f))))))

(deftest check-memcached-banner-exposure-test
  (testing "memcached banner flagged; clean body fine"
    (is (= 1 (count (passive/check-memcached-banner-exposure {:url "https://h/"} {:body "memcached"}))))
    (is (= 1 (count (passive/check-memcached-banner-exposure {:url "https://h/"} {:body "Memcached 1.6.19"}))))
    (is (empty? (passive/check-memcached-banner-exposure {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40100" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "memcached"})))]
      (is (some? f))
      (is (= "40100" (:rule-id f)))
      (is (= "CWE-209" (:cwe f))))))

(deftest check-tomcat-banner-exposure-test
  (testing "tomcat banner flagged; clean body fine"
    (is (= 1 (count (passive/check-tomcat-banner-exposure {:url "https://h/"} {:body "Apache Tomcat/9.0.90"}))))
    (is (= 1 (count (passive/check-tomcat-banner-exposure {:url "https://h/"} {:body "apache tomcat/10.1.0"}))))
    (is (empty? (passive/check-tomcat-banner-exposure {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40101" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "Apache Tomcat/8.5.0"})))]
      (is (some? f))
      (is (= "40101" (:rule-id f)))
      (is (= "CWE-209" (:cwe f))))))

(deftest check-nginx-banner-exposure-test
  (testing "nginx banner flagged; clean body fine"
    (is (= 1 (count (passive/check-nginx-banner-exposure {:url "https://h/"} {:body "nginx/1.24.0"}))))
    (is (= 1 (count (passive/check-nginx-banner-exposure {:url "https://h/"} {:body "nginx/1.18.0 (Ubuntu)"}))))
    (is (empty? (passive/check-nginx-banner-exposure {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40102" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "nginx/1.20.1"})))]
      (is (some? f))
      (is (= "40102" (:rule-id f)))
      (is (= "CWE-209" (:cwe f))))))

(deftest check-apache-banner-exposure-test
  (testing "apache banner flagged; clean body fine"
    (is (= 1 (count (passive/check-apache-banner-exposure {:url "https://h/"} {:body "Apache/2.4.52 (Ubuntu)"}))))
    (is (= 1 (count (passive/check-apache-banner-exposure {:url "https://h/"} {:body "Apache/2.4.41"}))))
    (is (empty? (passive/check-apache-banner-exposure {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40103" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "Apache/2.4.49"})))]
      (is (some? f))
      (is (= "40103" (:rule-id f)))
      (is (= "CWE-209" (:cwe f))))))

(deftest check-iis-banner-exposure-test
  (testing "iis banner flagged; clean body fine"
    (is (= 1 (count (passive/check-iis-banner-exposure {:url "https://h/"} {:body "Microsoft-IIS/10.0"}))))
    (is (= 1 (count (passive/check-iis-banner-exposure {:url "https://h/"} {:body "microsoft-iis/8.5"}))))
    (is (empty? (passive/check-iis-banner-exposure {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40104" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "Microsoft-IIS/7.5"})))]
      (is (some? f))
      (is (= "40104" (:rule-id f)))
      (is (= "CWE-209" (:cwe f))))))

(deftest check-php-version-exposure-test
  (testing "php version flagged; clean body fine"
    (is (= 1 (count (passive/check-php-version-exposure {:url "https://h/"} {:body "PHP Version 8.2.12"}))))
    (is (= 1 (count (passive/check-php-version-exposure {:url "https://h/"} {:body "php version 7.4.33"}))))
    (is (empty? (passive/check-php-version-exposure {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40105" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "PHP Version 8.1.0"})))]
      (is (some? f))
      (is (= "40105" (:rule-id f)))
      (is (= "CWE-209" (:cwe f))))))

(deftest check-sqlite-version-exposure-test
  (testing "sqlite version flagged; clean body fine"
    (is (= 1 (count (passive/check-sqlite-version-exposure {:url "https://h/"} {:body "SQLite version 3.45.0"}))))
    (is (= 1 (count (passive/check-sqlite-version-exposure {:url "https://h/"} {:body "sqlite version 3.40.1"}))))
    (is (empty? (passive/check-sqlite-version-exposure {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40106" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "SQLite version 3.43.2"})))]
      (is (some? f))
      (is (= "40106" (:rule-id f)))
      (is (= "CWE-209" (:cwe f))))))


(deftest check-vendor-exposure-test
  (testing "vendor exposed flagged; clean body fine"
    (is (= 1 (count (passive/check-vendor-exposure {:url "https://h/"} {:body "vendor/autoload.php"}))))
    (is (= 1 (count (passive/check-vendor-exposure {:url "https://h/"} {:body "vendor/guzzlehttp"}))))
    (is (empty? (passive/check-vendor-exposure {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40108" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "vendor/"})))]
      (is (some? f))
      (is (= "40108" (:rule-id f)))
      (is (= "CWE-552" (:cwe f))))))










(deftest check-sensitive-file-exposure-test
  (testing "sensitive files flagged; clean body fine"
    (is (= 1 (count (passive/check-sensitive-file-exposure {:url "https://h/"} {:body "package.json"}))))
    (is (= 1 (count (passive/check-sensitive-file-exposure {:url "https://h/"} {:body "composer.json"}))))
    (is (= 1 (count (passive/check-sensitive-file-exposure {:url "https://h/"} {:body ".htaccess"}))))
    (is (empty? (passive/check-sensitive-file-exposure {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40117" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "package.json"})))]
      (is (some? f))
      (is (= "40117" (:rule-id f)))
      (is (= "CWE-552" (:cwe f))))))

(deftest check-wpconfig-exposure-test
  (testing "wp-config.php flagged; clean body fine"
    (is (= 1 (count (passive/check-wpconfig-exposure {:url "https://h/"} {:body "wp-config.php"}))))
    (is (= 1 (count (passive/check-wpconfig-exposure {:url "https://h/"} {:body "/wp-config.php"}))))
    (is (empty? (passive/check-wpconfig-exposure {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40118" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "wp-config.php"})))]
      (is (some? f))
      (is (= "40118" (:rule-id f)))
      (is (= "CWE-552" (:cwe f))))))

(deftest check-webconfig-exposure-test
  (testing "web.config flagged; clean body fine"
    (is (= 1 (count (passive/check-webconfig-exposure {:url "https://h/"} {:body "web.config"}))))
    (is (= 1 (count (passive/check-webconfig-exposure {:url "https://h/"} {:body "/web.config"}))))
    (is (empty? (passive/check-webconfig-exposure {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40119" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "web.config"})))]
      (is (some? f))
      (is (= "40119" (:rule-id f)))
      (is (= "CWE-552" (:cwe f))))))

(deftest check-yarnlock-exposure-test
  (testing "yarn.lock flagged; clean body fine"
    (is (= 1 (count (passive/check-yarnlock-exposure {:url "https://h/"} {:body "yarn.lock"}))))
    (is (= 1 (count (passive/check-yarnlock-exposure {:url "https://h/"} {:body "/yarn.lock"}))))
    (is (empty? (passive/check-yarnlock-exposure {:url "https://h/"} {:body "hello"})))
    (let [f (first (filter #(= "40120" (:rule-id %)) (passive/passive-scan {:url "https://h/"} {:status 200 :headers {} :body "yarn.lock"})))]
      (is (some? f))
      (is (= "40120" (:rule-id f)))
      (is (= "CWE-552" (:cwe f))))))
