(ns mithril.web-scanner.active
  "Active scanner — injects detection payloads into request parameters and
  classifies responses. Items map to
  IPA「ウェブ健康診断仕様」 injection categories (SQLi, XSS, OS command
  injection, path traversal, CRLF).

  Safety contract: this library only ever produces *request descriptions* and
  verdicts. The actual sending is the injected `send-fn` effect (host side),
  behind an active-mode approval and URL scope check.
  Detection is evidence-based (marker reflection / differential response),
  never time-based guessing."
  (:require [clojure.string :as str]
            [mithril.web-scanner.core :as core]
            [mithril.web-scanner.authorization :as authorization]))

;; ---- payload tables (detection-grade, benign; no destructive payloads) ----

(def sqli-payloads
  "Error-based SQLi detection strings (IPA No.1-6). Evidence = SQL error echo."
  [{:p "' " :re #"(?i)(SQL syntax|SQLSTATE|syntax error|unterminated quoted string|ORA-\d{5}|MySQLSyntaxErrorException|PSQLException|Microsoft OLE DB|DB-Library|ODBC SQL Server Driver|Unclosed quotation mark|SQLite3::)"}
   {:p "1' OR '1'='1" :re #"(?i)SQL syntax|SQLSTATE"}
   {:p "1 OR 1=1" :re #"(?i)SQL syntax|SQLSTATE"}
   {:p "') OR 1=1--" :re #"(?i)SQL syntax|SQLSTATE|ORA-\d{5}"}
   {:p "1 AND 1=1" :re #"(?i)SQL syntax|SQLSTATE|unterminated"}
   {:p "' OR 1=1 OFFSET 0" :re #"(?i)(PostgreSQL|SQLite3::|syntax error|SQLSTATE)"}
   {:p "' UNION SELECT NULL,NULL--" :re #"(?i)(PostgreSQL|SQLite3::|syntax error|SQLSTATE|Microsoft OLE DB)"}
   {:p "' AND 1=CAST((1 AS INT))" :re #"(?i)(SQL Server|Microsoft OLE DB|syntax error)"}
   {:p "1'/**/OR/**/1=1--" :re #"(?i)(SQL syntax|SQLSTATE|syntax error)"}
   {:p "1%27%20OR%201=1--" :re #"(?i)(SQL syntax|SQLSTATE|syntax error)"}
   {:p "1') UNION SELECT NULL,NULL--" :re #"(?i)(PostgreSQL|SQLite3::|syntax error|SQLSTATE)"}
   {:p "1' UNION ALL SELECT NULL,1-- " :re #"(?i)(UNION ALL|syntax error|SQLSTATE)"}
   {:p "'||1=1--" :re #"(?i)(SQL syntax|SQLSTATE|syntax error)"}
   ;; blind / time-based / stacked variants (error-differential evidence)
   {:p "' AND 1=1-- -" :re #"(?i)(SQL syntax|SQLSTATE|syntax error|boolean)"}
   {:p "1; SELECT 1" :re #"(?i)(SQL syntax|SQLSTATE|syntax error|multiple statements)"}
   {:p "' AND 1=CAST(1 AS INT)--" :re #"(?i)(SQL syntax|SQLSTATE|casting|syntax error)"}])

(def xss-payloads
  "Reflected XSS markers (IPA No.18-24). Evidence = our unique marker echoed
  unescaped in the response body."
  [{:p "zappx\"><script>zpx1699()</script>" :re #"(?i)<script>zpx1699\(\)</script>"}
   {:p "zappx\" onerror=zpx1699() x=\"" :re #"(?i)onerror=zpx1699\(\)"}
   {:p "<svg onload=zpx1699()>" :re #"(?i)<svg onload=zpx1699\(\)>"}
   {:p "<img src=x onerror=zpx1699()>" :re #"(?i)onerror=zpx1699\(\)"}
   {:p "<details open ontoggle=zpx1699()>" :re #"(?i)ontoggle=zpx1699\(\)"}
   {:p "<iframe/onfocus=zpx1699() autofocus>" :re #"(?i)onfocus=zpx1699\(\)"}
   {:p "<audio src=x onerror=zpx1699()>" :re #"(?i)onerror=zpx1699\(\)"}
   {:p "<video><source onerror=zpx1699()>" :re #"(?i)onerror=zpx1699\(\)"}
   {:p "<body/onload=zpx1699()>" :re #"(?i)/onload=zpx1699\(\)"}
   {:p "<iframe src=javascript:zpx1699()>" :re #"(?i)src=javascript:zpx1699\(\)"}
   {:p "<a href=javascript:zpx1699()>x</a>" :re #"(?i)href=javascript:zpx1699\(\)"}
   {:p "<svg><animate onbegin=zpx1699() attributeName=x>" :re #"(?i)onbegin=zpx1699\(\)"}
   {:p "<math><mtext><script>zpx1699()</script>" :re #"(?i)<script>zpx1699\(\)</script>"}
   {:p "<base href=javascript:zpx1699()>" :re #"(?i)javascript:zpx1699\(\)"}
   ;; stored / header-or-cookie reflection variants (marker evidence only)
   {:p "<script>zpx1699()</script>" :re #"(?i)<script>zpx1699\(\)</script>"}
   {:p "zpx1699" :re #"(?i)zpx1699"}
   {:p "zpx1699\" onmouseover=\"zpx1699()" :re #"(?i)onmouseover=zpx1699"}])

(def cmdi-payloads
  "OS command injection detection (IPA No.7-17). Evidence = marker arithmetic
  result echoed (e.g. `echo zpx$((31+11))` → zpx42)."
  [{:p "; echo zpx$((31+11))" :re #"zpx42"}
   {:p "| echo zpx$((31+11))" :re #"zpx42"}
   {:p "`echo zpx$((31+11))`" :re #"zpx42"}
   {:p "&& echo zpx$((31+11))" :re #"zpx42"}
   {:p "$(echo zpx$((31+11)))" :re #"zpx42"}
   {:p ";${IFS}echo${IFS}zpx$((31+11))" :re #"zpx42"}
   {:p "%0aecho zpx$((31+11))" :re #"zpx42"}
   {:p "|| echo zpx$((31+11))" :re #"zpx42"}
   {:p "&& id" :re #"(?i)(uid=\d+\(|uid=\d+ )"}
   {:p ";id" :re #"(?i)uid=\d+\(gid=\d+\)"}
   {:p "& echo zpx42" :re #"zpx42"}
   ;; write/bash + Windows idiom variants (marker evidence only)
   {:p ";echo zpx$((31+11)) > /tmp/zpx1699" :re #"zpx42|zpx1699"}
   {:p "|findstr zpx1699" :re #"(?i)zpx1699"}
   {:p "%0aecho zpx$((31+11))" :re #"zpx42"}])

(def trav-payloads
  "Path traversal / LFI (IPA No.29-35). Evidence = canonical file content sentinel."
  [{:p "../../../../etc/passwd" :re #"root:[x*]?:0:0:"}
   {:p "..%2f..%2f..%2f..%2fetc%2fpasswd" :re #"root:[x*]?:0:0:"}
   {:p "/etc/passwd" :re #"root:[x*]?:0:0:"}
   {:p "..\\..\\..\\etc\\passwd" :re #"root:[x*]?:0:0:"}
   {:p "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd" :re #"root:[x*]?:0:0:"}
   {:p "../../../../../etc/passwd" :re #"root:[x*]?:0:0:"}
   {:p "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd" :re #"root:[x*]?:0:0:"}
   {:p "....//....//....//....//etc/passwd" :re #"root:[x*]?:0:0:"}
   {:p "file:///etc/passwd" :re #"root:[x*]?:0:0:"}
   {:p "..%5c..%5c..%5cetc%5cpasswd" :re #"root:[x*]?:0:0:"}
   {:p "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd" :re #"root:[x*]?:0:0:"}
   {:p "..;/..;/..;/etc/passwd" :re #"root:[x*]?:0:0:"}
   {:p "C:\\windows\\win.ini" :re #"(?i)\[fonts\]"}
   {:p "/etc/shadow" :re #"(?i)shadow:[x!*]?:\d+:"}
   {:p "%252e%252e%252f%252e%252e%252fetc%252fpasswd" :re #"root:[x*]?:0:0:"}
   ;; write / bash-injection-in-name variants (sentinel evidence only)
   {:p "....//....//....//etc/passwd" :re #"root:[x*]?:0:0:"}
   {:p "..%c1%9c..%c1%9cetc%c1%9cpasswd" :re #"root:[x*]?:0:0:"}
   {:p "/etc/passwd%00.txt" :re #"root:[x*]?:0:0:"}])

(def crlf-payloads
  "CRLF injection (IPA No.15-17). Evidence = our marker appearing as a header."
  [{:p "zpx\r\nX-ZapProbe: 1" :re #"(?i)x-zapprobe"}
   {:p "zpx%0d%0aX-ZapProbe: 1" :re #"(?i)x-zapprobe"}
   {:p "zpx\nX-ZapProbe: 1" :re #"(?i)x-zapprobe"}
   {:p "zpx%250d%250aX-ZapProbe: 1" :re #"(?i)x-zapprobe"}
   {:p "zpx%0dX-ZapProbe: 1" :re #"(?i)x-zapprobe"}
   {:p "zpx%0aX-ZapProbe: 1" :re #"(?i)x-zapprobe"}
   {:p "zpx\r%0aX-ZapProbe: 1" :re #"(?i)x-zapprobe"}
   {:p "zpx%0d%0a%0d%0aX-ZapProbe: 1" :re #"(?i)x-zapprobe"}
   {:p "zpx%0D%0AX-ZapProbe: 1" :re #"(?i)x-zapprobe"}
   {:p "zpx%0D%0ASet-Cookie:%20hoax=1" :re #"(?i)hoax=1"}
   {:p "zpx%0AX-ZapProbe: 1" :re #"(?i)x-zapprobe"}
   {:p "zpx%0D%0AX-ZapProbe: hoax=42" :re #"(?i)hoax=42"}
   ;; cookie / header injection variants (marker-as-header evidence only)
   {:p "zpx%0d%0aSet-Cookie:%20zpx1699=1" :re #"(?i)zpx1699=1"}
   {:p "zpx%3d%22%0d%0aX-ZapProbe: zpx1699" :re #"(?i)zpx1699"}])


(def ssrf-payloads
  "SSRF detection: benign internal-marker URLs only (no real internal target).
  Evidence = marker acknowledgement echoed in response."
  [{:p "http://zpx1699.invalid/" :re #"(?i)zpx1699"}
   {:p "http://169.254.169.254/latest/meta-data/" :re #"(?i)(zpx1699|meta-data|169\.254)"}
   {:p "http://localhost/zpx1699" :re #"(?i)zpx1699"}])

(def rfi-payloads
  "Remote File Inclusion detection: benign external-marker URLs only.
  Evidence = marker echoed; no remote file is ever loaded by this library."
  [{:p "http://zpx1699.invalid/rfi.txt" :re #"(?i)zpx1699"}
   {:p "https://zpx1699.invalid/x.txt" :re #"(?i)zpx1699"}
   {:p "//zpx1699.invalid/x.txt" :re #"(?i)zpx1699"}])

(def deser-payloads
  "Unsafe deserialization detection: benign marker bytes only (no shell /
  no object graph). Evidence = deserializer error marker echo."
  [{:p "zpx1699" :re #"(?i)(zpx1699|ObjectInputStream|pickle|Serializable)"}
   {:p "ACED" :re #"(?i)(ObjectInputStream|Serializable|zpx1699)"}
   {:p "cos-system-zpx1699" :re #"(?i)(pickle|zpx1699)"}])

(def rule-families
  [{:family :sqli :rule-id "40018" :cwe "CWE-89" :severity :high :title "SQL Injection (IPA インジェクション)"
    :payloads sqli-payloads}
   {:family :xss :rule-id "40012" :cwe "CWE-79" :severity :high :title "Cross-Site Scripting, reflected (IPA XSS)"
    :payloads xss-payloads}
   {:family :cmdi :rule-id "40014" :cwe "CWE-78" :severity :high :title "OS Command Injection (IPA コマンドインジェクション)"
    :payloads cmdi-payloads}
   {:family :trav :rule-id "40019" :cwe "CWE-22" :severity :high :title "Path Traversal (IPA パストラバーサル)"
    :payloads trav-payloads}
   {:family :ssti :rule-id "40021" :cwe "CWE-94" :severity :high :title "Server-Side Template Injection"
    :payloads [{:p "{{7*7}}" :re #"(?i)49"}
                {:p "${7*7}" :re #"(?i)49"}
                {:p "<%= 7*7 %>" :re #"(?i)49"}
                {:p "#{7*7}" :re #"(?i)49"}
                {:p "{{7*7}}zpx1699" :re #"(?i)(49|zpx1699)"}
                {:p "${7*7}zpx1699" :re #"(?i)(49|zpx1699)"}]}
   {:family :xxe :rule-id "40020" :cwe "CWE-611" :severity :high :title "XML External Entity Injection"
    :payloads [{:p "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">" :re #"root:[x*]?:0:0:"}
                {:p "<!ENTITY % xxe SYSTEM \"http://zpx1699.invalid/\">" :re #"(?i)SYSTEM"}
                {:p "<!DOCTYPE foo [<!ENTITY xxe \"zpx1699\">]>" :re #"(?i)zpx1699"}]}
   {:family :ldap :rule-id "40022" :cwe "CWE-90" :severity :high :title "LDAP Injection"
    :payloads [{:p "*)" :re #"(?i)zpx1699"}
                {:p "*)(&" :re #"(?i)zpx1699"}
                {:p "*))(|(objectClass=*" :re #"(?i)zpx1699"}]}
   {:family :nosqli :rule-id "40023" :cwe "CWE-943" :severity :high :title "NoSQL Injection"
    :payloads [{:p "{\"$ne\": null}" :re #"(?i)zpx1699"}
                {:p "{\"$gt\": \"\"}" :re #"(?i)zpx1699"}
                {:p "{\"$regex\": \".*\"}" :re #"(?i)zpx1699"}]}
   {:family :el :rule-id "40024" :cwe "CWE-917" :severity :high :title "Expression Language Injection"
    :payloads [{:p "${7*7}" :re #"(?i)49"}
                {:p "#{7*7}" :re #"(?i)49"}
                {:p "${7*'7'}" :re #"(?i)49"}]}
   {:family :crlf :rule-id "40016" :cwe "CWE-113" :severity :medium :title "CRLF Injection (IPA CRLFインジェクション)"
    :payloads crlf-payloads}
   {:family :rfi :rule-id "40025" :cwe "CWE-918" :severity :high :title "Remote File Inclusion (marker-based detection)"
    :payloads rfi-payloads}
   {:family :ssrf :rule-id "40026" :cwe "CWE-918" :severity :high :title "Server-Side Request Forgery (marker-based detection)"
    :payloads ssrf-payloads}
   {:family :deser :rule-id "40027" :cwe "CWE-502" :severity :high :title "Deserialization (marker/error-based detection)"
    :payloads deser-payloads}])

(defn parse-params
  "Split a URL query string into [{name value}]. Params are what we mutate."
  [url]
  (let [[_ q] (re-find #"\?([^#]*)" url)]
    (if (nil? q)
      []
      (->> (str/split q #"&")
           (map (fn [kv] (let [[k v] (str/split kv #"=" 2)] {:name k :value (or v "")})))
           vec))))

(defn- substitute
  "Replace one parameter's value in the URL."
  [url {:keys [name]} payload]
  (let [[base q] (str/split url #"\?" 2)]
    (if (nil? q)
      url
      (str base "?"
           (->> (str/split q #"&")
                (map (fn [kv]
                       (let [[k _] (str/split kv #"=" 2)]
                         (if (= k name) (str k "=" payload) kv))))
                (str/join "&"))))))

(defn active-scan
  "Run all active rule families against one URL. `send-fn` is the injected
  effect: request-map -> response-map. Every probe sends its payload through
  send-fn and verifies the response against the family's evidence regex; a
  response containing the baseline behavior only is not a finding.

  Returns a vector of findings (see mithril.web-scanner.core/finding)."
  [{:keys [url send-fn baseline approval-id max-pages]
    :or {max-pages 1}}]
  (let [initial-scope (authorization/authorization-scope
                       approval-id url "active" max-pages)
        guarded-send (authorization/guarded-transport
                      approval-id "active" max-pages initial-scope send-fn)
        params (parse-params url)
        baseline-body (or (get baseline :body "") (try (:body (guarded-send {:method "GET" :url url :headers {} :body nil})) "" (catch #?(:clj Exception :cljs :default) _ "")))]
    (vec
     (for [param params
           {:keys [rule-id cwe severity title payloads]} rule-families
           {:keys [p re]} payloads
           :let [probe-url (substitute url param p)
                 resp (try (guarded-send {:method "GET" :url probe-url :headers {} :body nil})
                           (catch #?(:clj Exception :cljs :default) _ nil))
                 body (or (get resp :body "") "")]
           :when (and resp (re-find re body) (not= body baseline-body))]
       (core/finding {:rule-id rule-id
                      :cwe cwe
                      :severity severity
                      :title title
                      :evidence (str "param " (:name param) " payload " (pr-str p)
                                     " matched " (pr-str re))
                      :url url
                      :param (:name param)
                      :solution "Validate/sanitize the parameter server-side; use parameterized queries, contextual output encoding, and no shell composition."})))))

(defn response-signature
  "Content signature of a response for boolean differential analysis.
  nil-safe. Used only to compare true/false payload responses; no content
  is interpreted."
  [resp]
  (let [body (str (get resp :body ""))]
    {:status (get resp :status 0)
     :length (count body)
     :head (subs body 0 (min 200 (count body)))}))

(defn boolean-differential?
  "True when two responses differ enough to suggest a boolean injection
  differential (blind SQLi). Requires both responses present and either a
  status change or a body-length delta >= threshold (default 1).
  Pure comparison: no requests are sent by this fn."
  ([a b] (boolean-differential? a b 1))
  ([a b threshold]
   (if (or (nil? a) (nil? b))
     false
     (let [sa (response-signature a)
           sb (response-signature b)]
       (or (not= (:status sa) (:status sb))
           (>= (Math/abs (- (:length sa) (:length sb))) threshold))))))

(defn blind-sqli-evidence
  "Summarize a boolean differential as evidence text, or nil when there is
  no differential. No payload is executed here; the caller supplies the
  already-observed responses."
  [true-resp false-resp]
  (when (boolean-differential? true-resp false-resp)
    (let [sat (response-signature true-resp)
          saf (response-signature false-resp)]
      (str "boolean differential: status " (:status sat) " vs " (:status saf)
           "; length " (:length sat) " vs " (:length saf)))))

(def blind-true-payload
  "Canonical boolean-true probe value for blind SQLi differential scans."
  "zztrue-1=1")

(def blind-false-payload
  "Canonical boolean-false probe value for blind SQLi differential scans."
  "zzfalse-1=2")

(defn blind-sqli-scan
  "Run a boolean differential probe for one parameter using the injected
  send-fn. Sends exactly two requests (true/false payloads) and compares
  them with boolean-differential?. Returns a finding map when a
  differential is observed, else nil. No payload is executed by this fn
  itself beyond the two injected sends; no other side effects."
  [{:keys [url send-fn param-name baseline-body]}]
  (when (and url send-fn param-name)
    (let [base (if (some? (re-find #"[?]" url)) url (str url "?"))
          mk (fn [p] (str base (if (some? (re-find #"[?]" base)) "&" "") param-name "=" p))
          send (fn [u] (try (send-fn {:method "GET" :url u :headers {} :body nil})
                            (catch #?(:clj Exception :cljs :default) _ nil)))
          true-resp (send (mk blind-true-payload))
          false-resp (send (mk blind-false-payload))]
      (when (and true-resp false-resp (boolean-differential? true-resp false-resp))
        (core/finding {:rule-id 40012
                       :cwe "CWE-89"
                       :severity "Medium"
                       :title "SQL Injection (blind differential)"
                       :evidence (blind-sqli-evidence true-resp false-resp)
                       :url url
                       :param param-name
                       :solution "Use parameterized queries; do not concatenate input into SQL."})))))

(defn time-differential?
  "True when probe duration exceeds baseline by at least threshold-ms.
  Pure comparison of already-measured durations (milliseconds); no clock
  or sleep is performed here — the caller supplies measured values."
  ([baseline-ms probe-ms] (time-differential? baseline-ms probe-ms 1000))
  ([baseline-ms probe-ms threshold-ms]
   (and (number? baseline-ms) (number? probe-ms) (number? threshold-ms)
        (>= (- probe-ms baseline-ms) threshold-ms))))

(defn time-evidence
  "Evidence text for a time-based differential, or nil when below threshold.
  No request is sent by this fn."
  [baseline-ms probe-ms]
  (when (time-differential? baseline-ms probe-ms)
    (str "time differential: baseline " baseline-ms "ms vs probe " probe-ms "ms")))

(defn time-sqli-scan
  "Run a time-based probe description for one parameter. Does not sleep;
  it compares baseline-ms (caller-measured) against probe-ms (caller-
  measured after sending the delay payload through send-fn). When send-fn
  is provided it is invoked exactly once with the delay payload; timings
  must be supplied by the caller via :baseline-ms / :probe-ms because SCI
  has no reliable clock here. Returns a finding when above threshold."
  [{:keys [send-fn param-name baseline-ms probe-ms payload]
    :or {payload "zzdelay"}}]
  (when (and send-fn param-name)
    (try (send-fn {:method "GET" :url (str "?q=" payload) :headers {} :body nil})
         (catch #?(:clj Exception :cljs :default) _ nil))
    (when (time-differential? baseline-ms probe-ms)
      (core/finding {:rule-id 40012
                     :cwe "CWE-89"
                     :severity "Medium"
                     :title "SQL Injection (time-based)"
                     :evidence (time-evidence baseline-ms probe-ms)
                     :url nil
                     :param param-name
                     :solution "Use parameterized queries; do not concatenate input into SQL."}))))

(def union-probe-payload "' UNION SELECT 1--")

(defn union-probe-params
  "Build query params for a UNION column-count probe. Pure: returns the
  probe value for the given param name; no request is sent."
  [param-name]
  {param-name union-probe-payload})

(defn union-evidence
  "Evidence text when a UNION probe response contains the injected
  literal column marker but the baseline does not. Pure inspection.
  The marker UNIONMARKER is embedded in the probe by union-probe-nul
  decoration up front when the caller wants reflection detection."
  [baseline-body probe-body]
  (let [b (str baseline-body)
        p (str probe-body)]
    (when (and (nil? (re-find #"UNIONMARKER" b))
               (some? (re-find #"UNIONMARKER" p)))
      "union probe marker reflected in response")))

(defn union-sqli-scan
  "Run a UNION column-count probe for one parameter using the injected
  send-fn. Sends exactly one request (the UNION probe payload) and
  inspects the response for the reflected marker. Returns a finding map
  when the marker appears, else nil. No payload is executed by this fn
  itself beyond the one injected send; no other side effects."
  [{:keys [url send-fn param-name baseline-body]}]
  (when (and url send-fn param-name)
    (let [base (if (some? (re-find #"[?]" url)) url (str url "?"))
          mk (fn [p] (str base (if (some? (re-find #"[?]" base)) "&" "") param-name "=" p))
          send (fn [u] (try (send-fn {:method "GET" :url u :headers {} :body nil})
                            (catch #?(:clj Exception :cljs :default) _ nil)))
          probe-resp (send (mk union-probe-payload))]
      (when probe-resp
        (when-let [ev (union-evidence baseline-body (get probe-resp :body ""))]
          (core/finding {:rule-id 40013
                         :cwe "CWE-89"
                         :severity "Medium"
                         :title "SQL Injection (UNION probe)"
                         :evidence ev
                         :url url
                         :param param-name
                         :solution "Use parameterized queries; do not concatenate input into SQL."}))))))

(defn error-sqli-evidence
  "Evidence text when a response body contains a database error
  signature (SQL syntax / SQLSTATE / ORA-xxxxx / etc.). Pure inspection;
  no request is sent. Returns nil when no signature matches."
  [probe-body]
  (let [m (re-find #"(?i)(SQL syntax|SQLSTATE|syntax error|unterminated quoted string|ORA-[0-9]{5}|MySQLSyntaxErrorException|PSQLException|SQLite3::)" (str probe-body))]
    (when m
      (str "db error signature: " (subs (str m) 0 (min 40 (count (str m))))))))

(defn reflection-evidence
  "Evidence text when the probe marker is reflected verbatim in the
  response body. Pure inspection; no request is sent. Callers inject a
  unique marker via send-fn payloads to detect reflection."
  [probe-body marker]
  (when (and marker (some? (re-find (re-pattern (str "(?i)" marker)) (str probe-body))))
    (str "reflected marker: " marker)))

(def xss-marker "zz9marker")

(defn xss-reflection-scan
  "Reflected-XSS probe for one parameter using the injected send-fn.
  Sends exactly one request carrying the benign marker and inspects the
  response for verbatim reflection. Returns a finding map when the
  marker appears, else nil. No other side effects."
  [{:keys [url send-fn param-name]}]
  (when (and url send-fn param-name)
    (let [base (if (some? (re-find #"[?]" url)) url (str url "?"))
          mk (fn [p] (str base (if (some? (re-find #"[?]" base)) "&" "") param-name "=" p))
          send (fn [u] (try (send-fn {:method "GET" :url u :headers {} :body nil})
                            (catch #?(:clj Exception :cljs :default) _ nil)))
          probe-resp (send (mk xss-marker))]
      (when probe-resp
        (when-let [ev (reflection-evidence (get probe-resp :body "") xss-marker)]
          (core/finding {:rule-id 40012
                         :cwe "CWE-79"
                         :severity "Medium"
                         :title "XSS reflection probe"
                         :evidence ev
                         :url url
                         :param param-name
                         :solution "Encode output; use context-aware encoding."}))))))

(def ssti-probe-payload "{{7*7}}")

(defn ssti-evidence
  "Evidence text when the probe evaluation 49 appears in the response
  but not the baseline. Pure inspection; no request is sent."
  [baseline-body probe-body]
  (let [b (str baseline-body)
        p (str probe-body)]
    (when (and (nil? (re-find #"[0-9]{2}" b))
               (some? (re-find #"(?<![0-9])49(?![0-9])" p)))
      "SSTI evaluation marker detected")))

(defn ssti-scan
  "SSTI probe for one parameter using the injected send-fn. Sends
  exactly one request carrying the benign probe and inspects the
  response. Returns a finding map when evaluation is detected, else nil."
  [{:keys [url send-fn param-name baseline-body]}]
  (when (and url send-fn param-name)
    (let [base (if (some? (re-find #"[?]" url)) url (str url "?"))
          mk (fn [p] (str base (if (some? (re-find #"[?]" base)) "&" "") param-name "=" p))
          send (fn [u] (try (send-fn {:method "GET" :url u :headers {} :body nil})
                            (catch #?(:clj Exception :cljs :default) _ nil)))
          probe-resp (send (mk ssti-probe-payload))]
      (when probe-resp
        (when-let [ev (ssti-evidence baseline-body (get probe-resp :body ""))]
          (core/finding {:rule-id 40029
                         :cwe "CWE-94"
                         :severity "Medium"
                         :title "SSTI probe"
                         :evidence ev
                         :url url
                         :param param-name
                         :solution "Do not pass user input as template code; sandbox/escape."}))))))

(def traversal-probe-path "../../zz9traversal")

(defn traversal-evidence
  "Evidence text when the response lists the probe marker path segment
  as a file entry (directory listing signal). Pure inspection."
  [probe-body]
  (let [b (str probe-body)]
    (when (some? (re-find #"(?i)zz9traversal" b))
      "traversal marker listed in response")))

(defn traversal-scan
  "Path traversal probe using the injected send-fn. Sends exactly one
  request carrying the benign probe path and inspects the response.
  Returns a finding map when the marker is listed, else nil."
  [{:keys [url send-fn]}]
  (when (and url send-fn)
    (let [base (if (some? (re-find #"[?]" url)) url (str url "?"))
          mk (fn [p] (str base (if (some? (re-find #"[?]" base)) "&" "") "p=" p))
          send (fn [u] (try (send-fn {:method "GET" :url u :headers {} :body nil})
                            (catch #?(:clj Exception :cljs :default) _ nil)))
          probe-resp (send (mk traversal-probe-path))]
      (when probe-resp
        (when-let [ev (traversal-evidence (get probe-resp :body ""))]
          (core/finding {:rule-id 40066
                         :cwe "CWE-22"
                         :severity "Medium"
                         :title "Path traversal probe"
                         :evidence ev
                         :url url
                         :solution "Canonicalize and allowlist paths; reject .. segments."}))))))

(def xxe-probe-payload "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe 'zz9xxe'>]><x>&xxe;</x>")

(defn xxe-evidence
  "Evidence text when the internal entity value zz9xxe is expanded in
  the response (it only appears expanded if the parser processed the
  DOCTYPE). Pure inspection; no request is sent."
  [baseline-body probe-body]
  (let [b (str baseline-body)
        p (str probe-body)]
    (when (and (nil? (re-find #"zz9xxe" b))
               (some? (re-find #"zz9xxe" p)))
      "XXE entity expansion detected")))

(defn xxe-scan
  "XXE probe using the injected send-fn. Sends exactly one request
  carrying the benign internal-entity probe and inspects the response.
  Returns a finding map when entity expansion is detected, else nil."
  [{:keys [url send-fn baseline-body]}]
  (when (and url send-fn)
    (let [send (fn [u] (try (send-fn {:method "POST" :url u :headers {} :body xxe-probe-payload})
                            (catch #?(:clj Exception :cljs :default) _ nil)))
          probe-resp (send (str url "?p=" xxe-probe-payload))]
      (when probe-resp
        (when-let [ev (xxe-evidence baseline-body (get probe-resp :body ""))]
          (core/finding {:rule-id 40067
                         :cwe "CWE-611"
                         :severity "Medium"
                         :title "XXE probe"
                         :evidence ev
                         :url url
                         :solution "Disable DOCTYPE/entity processing in XML parsers."}))))))

(def cmdi-probe-payload ";echo zz9cmdi")

(defn cmdi-evidence
  "Evidence text when the command output marker zz9cmdi appears in the
  response but not the baseline. Pure inspection; no request is sent."
  [baseline-body probe-body]
  (let [b (str baseline-body)
        p (str probe-body)]
    (when (and (nil? (re-find #"zz9cmdi" b))
               (some? (re-find #"zz9cmdi" p)))
      "CMDI echo marker in response")))

(defn cmdi-scan
  "CMDI probe using the injected send-fn. Sends exactly one request
  carrying the benign echo probe and inspects the response. Returns a
  finding map when the marker appears, else nil."
  [{:keys [url send-fn param-name baseline-body]}]
  (when (and url send-fn param-name)
    (let [base (if (some? (re-find #"[?]" url)) url (str url "?"))
          mk (fn [p] (str base (if (some? (re-find #"[?]" base)) "&" "") param-name "=" p))
          send (fn [u] (try (send-fn {:method "GET" :url u :headers {} :body nil})
                            (catch #?(:clj Exception :cljs :default) _ nil)))
          probe-resp (send (mk cmdi-probe-payload))]
      (when probe-resp
        (when-let [ev (cmdi-evidence baseline-body (get probe-resp :body ""))]
          (core/finding {:rule-id 40068
                         :cwe "CWE-78"
                         :severity "Medium"
                         :title "CMDI probe"
                         :evidence ev
                         :url url
                         :param param-name
                         :solution "Avoid shell invocation with user input; use exec without shell."}))))))

(def open-redirect-probe "//evil.example")

(defn open-redirect-evidence
  "Evidence text when the response Location header points off-site to
  the probe host. Pure inspection; no request is sent."
  [probe-location]
  (let [loc (str probe-location)]
    (when (and (some? (re-find #"(?i)^//evil\.example" loc))
               (some? (re-find #"evil\.example" loc)))
      (str "off-site redirect: " loc))))

(defn open-redirect-scan
  "Open redirect probe using the injected send-fn. Sends exactly one
  request carrying the benign probe value and inspects the Location
  header. Returns a finding map when an off-site redirect occurs, else
  nil."
  [{:keys [url send-fn param-name]}]
  (when (and url send-fn param-name)
    (let [base (if (some? (re-find #"[?]" url)) url (str url "?"))
          mk (fn [p] (str base (if (some? (re-find #"[?]" base)) "&" "") param-name "=" p))
          send (fn [u] (try (send-fn {:method "GET" :url u :headers {} :body nil})
                            (catch #?(:clj Exception :cljs :default) _ nil)))
          probe-resp (send (mk open-redirect-probe))]
      (when probe-resp
        (when-let [loc (or (get-in probe-resp [:headers "location"])
                           (get-in probe-resp [:headers "Location"])
                           (get-in probe-resp [:headers "LOCATION"]))]
          (when-let [ev (open-redirect-evidence loc)]
            (core/finding {:rule-id 40069
                           :cwe "CWE-601"
                           :severity "Medium"
                           :title "Open redirect probe"
                           :evidence ev
                           :url url
                           :param param-name
                           :solution "Allowlist redirect targets."})))))))

(def ldap-probe-payload "*")

(defn ldap-evidence
  "Evidence text when the probe response is materially larger than the
  baseline (wildcard match expansion). Pure inspection; no request is
  sent."
  [baseline-body probe-body]
  (let [b (count (str baseline-body))
        p (count (str probe-body))]
    (when (> p (* 2 (max b 1)))
      (str "response inflated: baseline " b " -> probe " p))))

(defn ldap-scan
  "LDAP injection probe using the injected send-fn. Sends exactly one
  request carrying the benign wildcard probe and inspects the response
  size. Returns a finding map when expansion is detected, else nil."
  [{:keys [url send-fn param-name baseline-body]}]
  (when (and url send-fn param-name)
    (let [base (if (some? (re-find #"[?]" url)) url (str url "?"))
          mk (fn [p] (str base (if (some? (re-find #"[?]" base)) "&" "") param-name "=" p))
          send (fn [u] (try (send-fn {:method "GET" :url u :headers {} :body nil})
                            (catch #?(:clj Exception :cljs :default) _ nil)))
          probe-resp (send (mk ldap-probe-payload))]
      (when probe-resp
        (when-let [ev (ldap-evidence baseline-body (get probe-resp :body ""))]
          (core/finding {:rule-id 40070
                         :cwe "CWE-90"
                         :severity "Medium"
                         :title "LDAP injection probe"
                         :evidence ev
                         :url url
                         :param param-name
                         :solution "Escape LDAP special characters in search filters."}))))))

(def crlf-probe-payload "%0d%0aX-Zz9-Probe:%20zz9crlf")

(defn crlf-evidence
  "Evidence text when the response headers echo the injected header
  name X-Zz9-Probe. Pure inspection; no request is sent."
  [probe-headers]
  (let [hs (get probe-headers "x-zz9-probe" (get probe-headers "X-Zz9-Probe"))]
    (when (some? hs)
      (str "injected header reflected: " (str hs)))))

(defn crlf-scan
  "CRLF injection probe using the injected send-fn. Sends exactly one
  request carrying the benign probe payload and inspects the response
  headers. Returns a finding map when the header is reflected, else nil."
  [{:keys [url send-fn param-name]}]
  (when (and url send-fn param-name)
    (let [base (if (some? (re-find #"[?]" url)) url (str url "?"))
          mk (fn [p] (str base (if (some? (re-find #"[?]" base)) "&" "") param-name "=" p))
          send (fn [u] (try (send-fn {:method "GET" :url u :headers {} :body nil})
                            (catch #?(:clj Exception :cljs :default) _ nil)))
          probe-resp (send (mk crlf-probe-payload))]
      (when probe-resp
        (when-let [ev (crlf-evidence (get probe-resp :headers {}))]
          (core/finding {:rule-id 40071
                         :cwe "CWE-113"
                         :severity "Medium"
                         :title "CRLF injection probe"
                         :evidence ev
                         :url url
                         :param param-name
                         :solution "Strip CR/LF from user input before use in headers."}))))))
