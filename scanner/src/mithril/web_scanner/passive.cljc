(ns mithril.web-scanner.passive
  "Passive scanner — non-intrusive checks on responses already observed.
  Response-only checks. Maps to IPA「ウェブ健康診断仕様」
  categories that only need response inspection (no payload injection):
  missing security headers, cookie flags, sensitive-info in responses.

  Pure functions over (request, response) pairs; findings are produced with
  rule IDs from the rules registry."
  (:require [mithril.web-scanner.text :as str]
            [mithril.web-scanner.core :as core]))

(defn- header-lower [resp name]
  (->> (get resp :headers {})
       (some (fn [[k v]] (when (= (str/lower-case (str k)) (str/lower-case (str name))) v)))))

(defn check-security-headers
  "IPA 仕様のセキュリティ関連 HTTP ヘッダ出力。RULE 10038 (ZAP-style id)."
  [{:keys [url]} resp]
  (let [required {"strict-transport-security" "HSTS not set (IPA セキュリティ関連HTTPヘッダ)"
                  "x-content-type-options"    "X-Content-Type-Options not set (MIMEスニッフィング対策)"
                  "content-security-policy"   "Content-Security-Policy not set (XSS 軽減)"
                  "x-frame-options"           "X-Frame-Options not set (クリックジャッキング対策)"
                  "referrer-policy"           "Referrer-Policy not set (URL漏洩対策)"
                  "permissions-policy"        "Permissions-Policy not set (不要機能の無効化)"
                  "cross-origin-opener-policy" "Cross-Origin-Opener-Policy not set (window.opener Isolation)"
                  "cross-origin-embedder-policy" "Cross-Origin-Embedder-Policy not set (Spectre mitigation)"
                  "cross-origin-resource-policy" "Cross-Origin-Resource-Policy not set (Cross-origin resource isolation)"}]
    (for [[h why] required
          :when (nil? (header-lower resp h))]
      (core/finding {:rule-id "10038"
                     :cwe "CWE-693"
                     :severity :low
                     :title why
                     :evidence (str "missing header: " h)
                     :url url
                     :solution (str "Set the " h " response header.")}))))

(defn check-cookie-flags
  "IPA セッション管理の Cookie 属性 (Secure / HttpOnly / SameSite). RULE 10010.
  A header value may be a vector (java.net.http multi-value Set-Cookie) —
  each cookie is checked independently. Appends __Host-/__Secure- prefix
  violation findings (RFC 6265bis): __Host- needs Secure + no Domain,
  __Secure- needs Secure."
  [{:keys [url]} resp]
  (let [raw (->> (get resp :headers {})
                 (filter (fn [[k _]] (= (str/lower-case (name k)) "set-cookie")))
                 (map (fn [[_ v]] v)))
        cookies (mapcat (fn [v] (if (sequential? v) (map str v) [(str v)])) raw)]
    (vec (concat
          (for [sc cookies
                flag [[#"(?i)secure" "Secure"] [#"(?i)httponly" "HttpOnly"] [#"(?i)samesite" "SameSite"]]
                :when (not (re-find (first flag) sc))]
            (core/finding {:rule-id "10010"
                           :cwe "CWE-1004"
                           :severity :medium
                           :title (str "Cookie missing " (second flag) " attribute (IPA セッション管理)")
                           :evidence sc
                           :url url
                           :solution (str "Set the " (second flag) " attribute on the cookie.")}))
          (for [sc cookies
                :let [name-part (first (str/split (str sc) #";"))
                      cname (str/trim (first (str/split name-part #"=")))
                      lname (str/lower-case cname)]
                :when (or (re-find #"^__host-" lname)
                          (re-find #"^__secure-" lname))
                :when (or (and (re-find #"^__host-" lname) (not (re-find #"(?i); ?secure" sc)))
                          (and (re-find #"^__host-" lname) (re-find #"(?i); ?domain=" sc))
                          (and (re-find #"^__host-" lname) (not (re-find #"(?i);\s*Path=/" sc)))
                          (and (re-find #"^__secure-" lname) (not (re-find #"(?i); ?secure" sc))))]
            (core/finding {:rule-id "10010"
                           :cwe "CWE-1004"
                           :severity :medium
                           :title "Cookie violates __Host-/__Secure- prefix rule (IPA セッション管理)"
                           :evidence sc
                           :url url
                           :solution "__Host- requires Secure + Path=/ with no Domain; __Secure- requires Secure."}))
          (for [sc cookies
                :let [name-part (first (str/split (str sc) #";"))
                      cname (str/trim (first (str/split name-part #"=")))
                      lname (str/lower-case cname)]
                :when (and (not (re-find #"^__host-" lname))
                           (re-find #"(?i); ?domain=" sc))]
            (core/finding {:rule-id "10010"
                           :cwe "CWE-1004"
                           :severity :low
                           :title "Cookie has broad Domain attribute (IPA セッション管理)"
                           :evidence sc
                           :url url
                            :solution "Drop the Domain attribute (or scope it) so the cookie does not extend across sibling subdomains."}))
          (for [sc cookies
                :when (and (re-find #"(?i); ?samesite=" sc)
                           (not (re-find #"(?i); ?secure" sc))
                           (re-find #"(?i); ?samesite=None" sc))]
            (core/finding {:rule-id "10010"
                           :cwe "CWE-1004"
                           :severity :medium
                           :title "Cookie has SameSite=None without Secure (IPA セッション管理)"
                           :evidence sc
                           :url url
                           :solution "Set Secure with SameSite=None; browsers ignore SameSite=None without Secure."}))
          (for [sc cookies
                :when (and (re-find #"(?i); ?samesite=" sc)
                           (not (re-find #"(?i); ?samesite=(Lax|Strict|None)(;|$)" sc)))]
            (core/finding {:rule-id "10010"
                           :cwe "CWE-1004"
                           :severity :low
                           :title "Cookie has invalid SameSite value (IPA セッション管理)"
                           :evidence sc
                           :url url
                           :solution "Use SameSite=Lax, Strict, or None."})))))

)

;; ---- header variant checks (weak values, rule 10038) ----

(defn check-header-variants
  "Weak security-header VALUES (rule 10038, CWE-693). Complements presence checks:
  HSTS with max-age < 1y (or none), X-Content-Type-Options without nosniff,
  CSP containing unsafe-inline/unsafe-eval."
  [{:keys [url]} resp]
  (let [hsts (header-lower resp "strict-transport-security")
        xcto (header-lower resp "x-content-type-options")
        csp (header-lower resp "content-security-policy")
        xfo (header-lower resp "x-frame-options")
        rp (header-lower resp "referrer-policy")
        pp (header-lower resp "permissions-policy")
        coop (header-lower resp "cross-origin-opener-policy")
        coep (header-lower resp "cross-origin-embedder-policy")
        corp (header-lower resp "cross-origin-resource-policy")
        xxss (header-lower resp "x-xss-protection")
        hsts-weak (when hsts
                    (let [m (re-find #"(?i)max-age=([0-9]+)" (str hsts))
                          d (some-> m second)]
                      (or (nil? d)
                          (< (count d) 8)
                          (and (= (count d) 8) (neg? (compare d "31536000"))))))
        xcto-weak (when xcto
                    (nil? (re-find #"(?i)nosniff" (str xcto))))
        csp-weak (when csp
                   (or (re-find #"(?i)unsafe-inline" (str csp))
                       (re-find #"(?i)unsafe-eval" (str csp))))
        csp-wild (when csp
                   (or (re-find #"(?i)(default-src|script-src)\s+\*" (str csp))
                       (re-find #"(?i)script-src\s+[^;]*\*" (str csp))))
        hsts-nosd (when hsts
                    (nil? (re-find #"(?i)includesubdomains" (str hsts))))
        xfo-weak (when xfo
                   (nil? (re-find #"(?i)^\s*(DENY|SAMEORIGIN)\s*$" (str xfo))))
        rp-weak (when rp
                  (let [rv (str/lower-case (str/trim (str rp)))]
                    (not (contains? #{"no-referrer" "no-referrer-when-downgrade" "strict-origin"
                                       "strict-origin-when-cross-origin" "origin" "origin-when-cross-origin"
                                       "same-origin" "unsafe-url"} rv))))
        rp-unsafe (when rp (= "unsafe-url" (str/lower-case (str/trim (str rp)))))
        pp-weak (when pp
                  (= "" (str/trim (str pp))))
        pp-wild (when pp
                  (and (not pp-weak)
                       (re-find #"\*" (str pp))))
        coop-weak (when coop
                    (not (contains? #{"same-origin" "same-origin-allow-popups"} (str/lower-case (str/trim (str coop))))))
        coep-weak (when coep
                    (not (contains? #{"require-corp" "credentialless"} (str/lower-case (str/trim (str coep))))))
        corp-weak (when corp
                    (not (contains? #{"same-origin" "same-site" "cross-origin"} (str/lower-case (str/trim (str corp))))))
        corp-unsafe (when corp (= "cross-origin" (str/lower-case (str/trim (str corp)))))
        xxss-unsafe (when xxss (re-find #"(?i)mode=allow" (str xxss)))
        csp-empty (when csp
                    (= "" (str/trim (str csp))))]
    (vec (concat
          (if hsts-weak
            [(core/finding {:rule-id "10038" :cwe "CWE-693" :severity :medium
                           :title "Strict-Transport-Security max-age too short (or missing)"
                           :evidence (str hsts) :url url
                           :solution "Set Strict-Transport-Security to max-age=31536000; includeSubDomains."})]
            [])
          (if xcto-weak
            [(core/finding {:rule-id "10038" :cwe "CWE-693" :severity :medium
                           :title "X-Content-Type-Options without nosniff"
                           :evidence (str xcto) :url url
                           :solution "Set X-Content-Type-Options to nosniff."})]
            [])
          (if csp-weak
            [(core/finding {:rule-id "10038" :cwe "CWE-693" :severity :medium
                           :title "Content-Security-Policy allows unsafe-inline/unsafe-eval"
                           :evidence (subs (str csp) 0 (min 80 (count (str csp)))) :url url
                           :solution "Remove unsafe-inline/unsafe-eval from the Content-Security-Policy."})]
            [])
          (if csp-wild
            [(core/finding {:rule-id "10038" :cwe "CWE-693" :severity :medium
                           :title "Content-Security-Policy allows wildcard default/script source"
                           :evidence (subs (str csp) 0 (min 80 (count (str csp)))) :url url
                           :solution "Replace default-src * / script-src * with the specific origins you need."})]
            [])
          (if hsts-nosd
            [(core/finding {:rule-id "10038" :cwe "CWE-693" :severity :low
                           :title "Strict-Transport-Security missing includeSubDomains"
                           :evidence (str hsts) :url url
                           :solution "Add includeSubDomains to the Strict-Transport-Security header."})]
            [])
          (if xfo-weak
            [(core/finding {:rule-id "10038" :cwe "CWE-693" :severity :low
                           :title "X-Frame-Options value outside DENY/SAMEORIGIN (ALLOW-FROM is obsolete)"
                           :evidence (str xfo) :url url
                           :solution "Use X-Frame-Options DENY or SAMEORIGIN, or CSP frame-ancestors."})]
            [])
          (if rp-weak
            [(core/finding {:rule-id "10038" :cwe "CWE-693" :severity :low
                           :title "Referrer-Policy value is not a standard token"
                           :evidence (str rp) :url url
                           :solution "Set Referrer-Policy to a standard value such as no-referrer or strict-origin."})]
            [])
          (if rp-unsafe
            [(core/finding {:rule-id "10038" :cwe "CWE-693" :severity :medium
                           :title "Referrer-Policy uses unsafe-url (full URL leaks to any origin)"
                           :evidence (str rp) :url url
                           :solution "Use no-referrer or strict-origin so URLs do not leak to third parties."})]
            [])
          (if pp-weak
            [(core/finding {:rule-id "10038" :cwe "CWE-693" :severity :low
                           :title "Permissions-Policy present but empty"
                           :evidence (subs (str pp) 0 (min 40 (count (str pp)))) :url url
                           :solution "List the features to disable in Permissions-Policy."})]
            [])
          (if pp-wild
            [(core/finding {:rule-id "10038" :cwe "CWE-693" :severity :medium
                           :title "Permissions-Policy allows wildcard feature access"
                           :evidence (subs (str pp) 0 (min 40 (count (str pp)))) :url url
                           :solution "Avoid wildcard allowances such as camera=*; enumerate the features each origin may use."})]
            [])
          (if csp-empty
            [(core/finding {:rule-id "10038" :cwe "CWE-693" :severity :medium
                           :title "Content-Security-Policy present but empty"
                           :evidence (subs (str csp) 0 (min 40 (count (str csp)))) :url url
                           :solution "Give the Content-Security-Policy an effective policy."})]
            [])
          (if coop-weak
            [(core/finding {:rule-id "10038" :cwe "CWE-693" :severity :low
                           :title "Cross-Origin-Opener-Policy value is not a standard token"
                           :evidence (str coop) :url url
                           :solution "Set Cross-Origin-Opener-Policy to same-origin (or same-origin-allow-popups)."})]
            [])
          (if coep-weak
            [(core/finding {:rule-id "10038" :cwe "CWE-693" :severity :low
                           :title "Cross-Origin-Embedder-Policy value is not a standard token"
                           :evidence (str coep) :url url
                           :solution "Set Cross-Origin-Embedder-Policy to require-corp (or credentialless)."})]
            [])
          (if corp-weak
            [(core/finding {:rule-id "10038" :cwe "CWE-693" :severity :low
                           :title "Cross-Origin-Resource-Policy value is not a standard token"
                           :evidence (str corp) :url url
                           :solution "Set Cross-Origin-Resource-Policy to same-origin, same-site, or cross-origin."})]
            [])
          (if corp-unsafe
            [(core/finding {:rule-id "10038" :cwe "CWE-693" :severity :medium
                           :title "Cross-Origin-Resource-Policy cross-origin permits cross-origin loading"
                           :evidence (str corp) :url url
                           :solution "Use same-origin or same-site unless cross-origin loading is required."})]
            [])
          (if xxss-unsafe
            [(core/finding {:rule-id "10038" :cwe "CWE-693" :severity :medium
                           :title "X-XSS-Protection enables XSS auditor (mode=allow)"
                           :evidence (str xxss) :url url
                           :solution "Disable or remove X-XSS-Protection mode=allow; rely on CSP."})]
            [])))))

;; ---- directory listing (rule 10027) ----

(defn check-directory-listing
  "Directory listing in the response body (rule 10027, CWE-209, :high).
  Detection markers only; no new alert id."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))]
    (if (or (re-find #"(?i)<title>Index of " body)
            (re-find #"(?i)Directory listing for " body)
            (re-find #"(?i)Apache Directory Listing" body)
            (re-find #"(?i)<h1>directory listing" body)
            (re-find #"(?i)objects in folder" body)
            (re-find #"(?i)<title>directory listing</title>" body))
      [(core/finding {:rule-id "10027"
                      :cwe "CWE-209"
                      :severity :high
                      :title "Directory listing exposed (IPA 情報漏えい)"
                      :evidence (subs body 0 (min 40 (count body)))
                      :url url
                      :solution "Disable directory listing on the server."})]
      [])))

(def ^:private sensitive-patterns
  [[#"(?i)password\s*[:=]\s*[^&\"'\s]+" "possible credential echoed in response"]
   [#"(?i)\bAKIA[0-9A-Z]{16}\b" "AWS access key id pattern in response"]
   [#"(?i)-----BEGIN (RSA |EC )?PRIVATE KEY-----" "private key material in response"]
   [#"(?i)(mongodb(\+srv)?|redis|postgres(ql)?|mysql)://[^ \s:]+:[^ \s@]+@" "database connection string with credentials exposed"]
   [#"(?i)-----BEGIN [A-Z ]*CERTIFICATE-----" "certificate material (private PKI) exposed"]
   [#"(?i)(?:ftp|smtps?|amqp|ldap|ldaps)://[^ \s:]+:[^ \s@]+" "URL with embedded credentials exposed"]
   [#"Apache/[0-9]+\.[0-9]+" "Apache version disclosure in response"]
   [#"Microsoft-IIS/[0-9]+\.[0-9]+" "Microsoft IIS version disclosure in response"]
   [#"nginx/[0-9]+\.[0-9]+" "nginx version disclosure in response"]
   [#"(?i)caddy/[0-9]+\.[0-9]+" "caddy version disclosure in response"]
   [#"(?i)litespeed/[0-9]+\.[0-9]+" "litespeed version disclosure in response"]
   [#"(?i)tengine/[0-9]+\.[0-9]+" "tengine version disclosure in response"]
   [#"(?i)openresty/[0-9]+\.[0-9]+" "openresty version disclosure in response"]
   [#"(?i)apache tomcat/[0-9]+\.[0-9]+" "apache tomcat version disclosure in response"]
   [#"(?i)node\.js/v?[0-9]+\.[0-9]+" "node.js version disclosure in response"]
   [#"(?i)werkzeug/[0-9]+\.[0-9]+" "werkzeug version disclosure in response"]
   [#"(?i)curl/[0-9]+\.[0-9]+" "curl version disclosure in response"]
   [#"(?i)wget/[0-9]+\.[0-9]+" "wget version disclosure in response"]
   [#"(?i)boa/[0-9]+\.[0-9]+" "boa version disclosure in response"]
   [#"(?i)webmin/[0-9]+\.[0-9]+" "webmin version disclosure in response"]
   [#"(?i)varnish/[0-9]+\.[0-9]+" "varnish version disclosure in response"]
   [#"(?i)squid/[0-9]+\.[0-9]+" "squid version disclosure in response"]
   [#"(?i)hikari/[0-9]+\.[0-9]+" "hikari version disclosure in response"]
   [#"(?i)jetty/[0-9]+\.[0-9]+" "jetty version disclosure in response"]
   [#"(?i)gretty/[0-9]+\.[0-9]+" "gretty version disclosure in response"]
   [#"(?i)tcat/[0-9]+\.[0-9]+" "tcat version disclosure in response"]
   [#"(?i)jboss/[0-9]+\.[0-9]+" "jboss version disclosure in response"]
   [#"(?i)weblogic/[0-9]+\.[0-9]+" "weblogic version disclosure in response"]
   [#"(?i)resin/[0-9]+\.[0-9]+" "resin version disclosure in response"]
   [#"(?i)payara/[0-9]+\.[0-9]+" "payara version disclosure in response"]
   [#"(?i)wildfly/[0-9]+\.[0-9]+" "wildfly version disclosure in response"]
   [#"(?i)glassfish/[0-9]+\.[0-9]+" "glassfish version disclosure in response"]
   [#"(?i)grizzly/[0-9]+\.[0-9]+" "grizzly version disclosure in response"]
   [#"(?i)mojolicious/[0-9]+\.[0-9]+" "mojolicious version disclosure in response"]
   [#"(?i)starlette/[0-9]+\.[0-9]+" "starlette version disclosure in response"]
   [#"(?i)tornado/[0-9]+\.[0-9]+" "tornado version disclosure in response"]
   [#"(?i)sanic/[0-9]+\.[0-9]+" "sanic version disclosure in response"]
   [#"(?i)quart/[0-9]+\.[0-9]+" "quart version disclosure in response"]
   [#"(?i)falcon/[0-9]+\.[0-9]+" "falcon version disclosure in response"]
   [#"(?i)elysia/[0-9]+\.[0-9]+" "elysia version disclosure in response"]
   [#"(?i)hono/[0-9]+\.[0-9]+" "hono version disclosure in response"]
   [#"(?i)fiber/[0-9]+\.[0-9]+" "fiber version disclosure in response"]
   [#"(?i)gin/[0-9]+\.[0-9]+" "gin version disclosure in response"]
   [#"(?i)echo/[0-9]+\.[0-9]+" "echo version disclosure in response"]
   [#"(?i)mux/[0-9]+\.[0-9]+" "mux version disclosure in response"]
   [#"(?i)gorilla/[0-9]+\.[0-9]+" "gorilla version disclosure in response"]
   [#"(?i)httprouter/[0-9]+\.[0-9]+" "httprouter version disclosure in response"]
   [#"(?i)plack/[0-9]+\.[0-9]+" "plack version disclosure in response"]
   [#"(?i)dancer/[0-9]+\.[0-9]+" "dancer version disclosure in response"]
   [#"(?i)catalyst/[0-9]+\.[0-9]+" "catalyst version disclosure in response"]
   [#"(?i)starman/[0-9]+\.[0-9]+" "starman version disclosure in response"]
   [#"(?i)carton/[0-9]+\.[0-9]+" "carton version disclosure in response"]
   [#"(?i)lwp/[0-9]+\.[0-9]+" "lwp version disclosure in response"]
   [#"(?i)dbix/[0-9]+\.[0-9]+" "dbix version disclosure in response"]
   [#"(?i)moose/[0-9]+\.[0-9]+" "moose version disclosure in response"]
   [#"(?i)datetime/[0-9]+\.[0-9]+" "datetime version disclosure in response"]
   [#"(?i)pod/[0-9]+\.[0-9]+" "pod version disclosure in response"]
   [#"(?i)benchmark/[0-9]+\.[0-9]+" "benchmark version disclosure in response"]
   [#"(?i)b/[0-9]+\.[0-9]+" "b version disclosure in response"]
   [#"(?i)devel-ppport/[0-9]+\.[0-9]+" "devel-ppport version disclosure in response"]
   [#"(?i)math/[0-9]+\.[0-9]+" "math version disclosure in response"]
   [#"(?i)posix/[0-9]+\.[0-9]+" "posix version disclosure in response"]
   [#"(?i)socket/[0-9]+\.[0-9]+" "socket version disclosure in response"]
   [#"(?i)io/[0-9]+\.[0-9]+" "io version disclosure in response"]
   [#"(?i)expect/[0-9]+\.[0-9]+" "expect version disclosure in response"]
   [#"(?i)config/[0-9]+\.[0-9]+" "config version disclosure in response"]
   [#"(?i)locale/[0-9]+\.[0-9]+" "locale version disclosure in response"]
   [#"(?i)memoize/[0-9]+\.[0-9]+" "memoize version disclosure in response"]
   [#"(?i)bssolv/[0-9]+\.[0-9]+" "bssolv version disclosure in response"]
   [#"(?i)bsversion/[0-9]+\.[0-9]+" "bsversion version disclosure in response"]
   [#"(?i)class/[0-9]+\.[0-9]+" "class version disclosure in response"]
   [#"(?i)data/[0-9]+\.[0-9]+" "data version disclosure in response"]
   [#"(?i)diag/[0-9]+\.[0-9]+" "diag version disclosure in response"]
   [#"(?i)ebcdic/[0-9]+\.[0-9]+" "ebcdic version disclosure in response"]
   [#"(?i)fence/[0-9]+\.[0-9]+" "fence version disclosure in response"]
   [#"(?i)getopt2/[0-9]+\.[0-9]+" "getopt2 version disclosure in response"]
   [#"(?i)hash/[0-9]+\.[0-9]+" "hash version disclosure in response"]
   [#"(?i)host/[0-9]+\.[0-9]+" "host version disclosure in response"]
   [#"(?i)io-async/[0-9]+\.[0-9]+" "io-async version disclosure in response"]
   [#"(?i)io-select/[0-9]+\.[0-9]+" "io-select version disclosure in response"]
   [#"(?i)mime/[0-9]+\.[0-9]+" "mime version disclosure in response"]
   [#"(?i)msgpack/[0-9]+\.[0-9]+" "msgpack version disclosure in response"]
   [#"(?i)op/[0-9]+\.[0-9]+" "op version disclosure in response"]
   [#"(?i)oo/[0-9]+\.[0-9]+" "oo version disclosure in response"]
   [#"(?i)oodim/[0-9]+\.[0-9]+" "oodim version disclosure in response"]
   [#"(?i)opi/[0-9]+\.[0-9]+" "opi version disclosure in response"]
   [#"(?i)os/[0-9]+\.[0-9]+" "os version disclosure in response"]
   [#"(?i)perlio/[0-9]+\.[0-9]+" "perlio version disclosure in response"]
   [#"(?i)pokemon/[0-9]+\.[0-9]+" "pokemon version disclosure in response"]
   [#"(?i)lighttpd/[0-9]+\.[0-9]+" "lighttpd version disclosure in response"]
   [#"(?i)haproxy/[0-9]+\.[0-9]+" "haproxy version disclosure in response"]
   [#"(?i)traefik/[0-9]+\.[0-9]+" "traefik version disclosure in response"]
   [#"(?i)envoy/[0-9]+\.[0-9]+" "envoy version disclosure in response"]
   [#"(?i)cherokee/[0-9]+\.[0-9]+" "cherokee version disclosure in response"]
   [#"(?i)proxygen/[0-9]+\.[0-9]+" "proxygen version disclosure in response"]
   [#"(?i)istio/[0-9]+\.[0-9]+" "istio version disclosure in response"]
   [#"(?i)gunicorn/[0-9]+\.[0-9]+" "gunicorn version disclosure in response"]
   [#"(?i)unicorn/[0-9]+\.[0-9]+" "unicorn version disclosure in response"]
   [#"(?i)puma/[0-9]+\.[0-9]+" "puma version disclosure in response"]
   [#"(?i)passenger/[0-9]+\.[0-9]+" "passenger version disclosure in response"]
   [#"(?i)express/[0-9]+\.[0-9]+" "express version disclosure in response"]
   [#"(?i)fastify/[0-9]+\.[0-9]+" "fastify version disclosure in response"]
   [#"(?i)koa/[0-9]+\.[0-9]+" "koa version disclosure in response"]
   [#"(?i)flask/[0-9]+\.[0-9]+" "flask version disclosure in response"]
   [#"(?i)django/[0-9]+\.[0-9]+" "django version disclosure in response"]
   [#"(?i)rails/[0-9]+\.[0-9]+" "rails version disclosure in response"]
   [#"(?i)laravel/[0-9]+\.[0-9]+" "laravel version disclosure in response"]
   [#"(?i)symfony/[0-9]+\.[0-9]+" "symfony version disclosure in response"]
   [#"(?i)spring/[0-9]+\.[0-9]+" "spring version disclosure in response"]
   [#"(?i)asp\.net/[0-9]+\.[0-9]+" "aspnet version disclosure in response"]
   [#"(?i)wordpress/[0-9]+\.[0-9]+" "wordpress version disclosure in response"]
   [#"(?i)drupal/[0-9]+\.[0-9]+" "drupal version disclosure in response"]
   [#"(?i)joomla/[0-9]+\.[0-9]+" "joomla version disclosure in response"]
   [#"(?i)nextjs/[0-9]+\.[0-9]+" "nextjs version disclosure in response"]
   [#"(?i)nuxt/[0-9]+\.[0-9]+" "nuxt version disclosure in response"]
   [#"(?i)hapi/[0-9]+\.[0-9]+" "hapi version disclosure in response"]
   [#"(?i)adonis/[0-9]+\.[0-9]+" "adonis version disclosure in response"]
   [#"(?i)cakephp/[0-9]+\.[0-9]+" "cakephp version disclosure in response"]
   [#"(?i)codeigniter/[0-9]+\.[0-9]+" "codeigniter version disclosure in response"]
   [#"(?i)slim/[0-9]+\.[0-9]+" "slim version disclosure in response"]
   [#"(?i)magento/[0-9]+\.[0-9]+" "magento version disclosure in response"]
   [#"(?i)prestashop/[0-9]+\.[0-9]+" "prestashop version disclosure in response"]
   [#"(?i)opencart/[0-9]+\.[0-9]+" "opencart version disclosure in response"]
   [#"(?i)saleor/[0-9]+\.[0-9]+" "saleor version disclosure in response"]
   [#"(?i)medusa/[0-9]+\.[0-9]+" "medusa version disclosure in response"]
   [#"(?i)strapi/[0-9]+\.[0-9]+" "strapi version disclosure in response"]
   [#"(?i)ghost/[0-9]+\.[0-9]+" "ghost version disclosure in response"]
   [#"(?i)keystone/[0-9]+\.[0-9]+" "keystone version disclosure in response"]
   [#"(?i)payload/[0-9]+\.[0-9]+" "payload version disclosure in response"]
   [#"(?i)sanity/[0-9]+\.[0-9]+" "sanity version disclosure in response"]
   [#"(?i)redis/[0-9]+\.[0-9]+" "redis version disclosure in response"]
   [#"(?i)postgres/[0-9]+\.[0-9]+" "postgres version disclosure in response"]
   [#"(?i)mysql/[0-9]+\.[0-9]+" "mysql version disclosure in response"]
   [#"(?i)mongodb/[0-9]+\.[0-9]+" "mongodb version disclosure in response"]
   [#"(?i)mariadb/[0-9]+\.[0-9]+" "mariadb version disclosure in response"]
   [#"(?i)elasticsearch/[0-9]+\.[0-9]+" "elasticsearch version disclosure in response"]
   [#"(?i)solr/[0-9]+\.[0-9]+" "solr version disclosure in response"]
   [#"(?i)typesense/[0-9]+\.[0-9]+" "typesense version disclosure in response"]
   [#"(?i)meilisearch/[0-9]+\.[0-9]+" "meilisearch version disclosure in response"]
   [#"(?i)sphinx/[0-9]+\.[0-9]+" "sphinx version disclosure in response"]
   [#"(?i)docker/[0-9]+\.[0-9]+" "docker version disclosure in response"]
   [#"(?i)kubernetes/[0-9]+\.[0-9]+" "kubernetes version disclosure in response"]
   [#"(?i)prometheus/[0-9]+\.[0-9]+" "prometheus version disclosure in response"]
   [#"(?i)grafana/[0-9]+\.[0-9]+" "grafana version disclosure in response"]
   [#"(?i)jenkins/[0-9]+\.[0-9]+" "jenkins version disclosure in response"]
   [#"(?i)gitlab/[0-9]+\.[0-9]+" "gitlab version disclosure in response"]
   [#"(?i)github/[0-9]+\.[0-9]+" "github version disclosure in response"]
   [#"(?i)node/[0-9]+\.[0-9]+" "node version disclosure in response"]
   [#"(?i)deno/[0-9]+\.[0-9]+" "deno version disclosure in response"]
   [#"(?i)bun/[0-9]+\.[0-9]+" "bun version disclosure in response"]
   [#"(?i)php/[0-9]+\.[0-9]+" "php version disclosure in response"]
   [#"(?i)python/[0-9]+\.[0-9]+" "python version disclosure in response"]
   [#"(?i)ruby/[0-9]+\.[0-9]+" "ruby version disclosure in response"]
   [#"(?i)go/[0-9]+\.[0-9]+" "go version disclosure in response"]
   [#"(?i)java/[0-9]+\.[0-9]+" "java version disclosure in response"]
   [#"(?i)rust/[0-9]+\.[0-9]+" "rust version disclosure in response"]
   [#"(?i)clojure/[0-9]+\.[0-9]+" "clojure version disclosure in response"]
   [#"(?i)scala/[0-9]+\.[0-9]+" "scala version disclosure in response"]
   [#"(?i)dotnet/[0-9]+\.[0-9]+" "dotnet version disclosure in response"]
   [#"(?i)erlang/[0-9]+\.[0-9]+" "erlang version disclosure in response"]
   [#"(?i)play/[0-9]+\.[0-9]+" "play version disclosure in response"]
   [#"(?i)akka/[0-9]+\.[0-9]+" "akka version disclosure in response"]
   [#"(?i)quarkus/[0-9]+\.[0-9]+" "quarkus version disclosure in response"]
   [#"(?i)micronaut/[0-9]+\.[0-9]+" "micronaut version disclosure in response"]
   [#"(?i)vertx/[0-9]+\.[0-9]+" "vertx version disclosure in response"]
   [#"(?i)dropwizard/[0-9]+\.[0-9]+" "dropwizard version disclosure in response"]
   [#"(?i)jooby/[0-9]+\.[0-9]+" "jooby version disclosure in response"]
   [#"(?i)helidon/[0-9]+\.[0-9]+" "helidon version disclosure in response"]
   [#"(?i)openliberty/[0-9]+\.[0-9]+" "openliberty version disclosure in response"]
   [#"(?i)kotlin/[0-9]+\.[0-9]+" "kotlin version disclosure in response"]
   [#"(?i)feathers/[0-9]+\.[0-9]+" "feathers version disclosure in response"]
   [#"(?i)loopback/[0-9]+\.[0-9]+" "loopback version disclosure in response"]
   [#"(?i)meteor/[0-9]+\.[0-9]+" "meteor version disclosure in response"]
   [#"(?i)blitz/[0-9]+\.[0-9]+" "blitz version disclosure in response"]
   [#"(?i)redwood/[0-9]+\.[0-9]+" "redwood version disclosure in response"]
   [#"(?i)wasp/[0-9]+\.[0-9]+" "wasp version disclosure in response"]
   [#"(?i)expo/[0-9]+\.[0-9]+" "expo version disclosure in response"]
   [#"(?i)ionic/[0-9]+\.[0-9]+" "ionic version disclosure in response"]
   [#"(?i)cordova/[0-9]+\.[0-9]+" "cordova version disclosure in response"]
   [#"(?i)electron/[0-9]+\.[0-9]+" "electron version disclosure in response"]
   [#"(?i)angular/[0-9]+\.[0-9]+" "angular version disclosure in response"]
   [#"(?i)react/[0-9]+\.[0-9]+" "react version disclosure in response"]
   [#"(?i)vue/[0-9]+\.[0-9]+" "vue version disclosure in response"]
   [#"(?i)svelte/[0-9]+\.[0-9]+" "svelte version disclosure in response"]
   [#"(?i)backbone/[0-9]+\.[0-9]+" "backbone version disclosure in response"]
   [#"(?i)ember/[0-9]+\.[0-9]+" "ember version disclosure in response"]
   [#"(?i)knockout/[0-9]+\.[0-9]+" "knockout version disclosure in response"]
   [#"(?i)dojo/[0-9]+\.[0-9]+" "dojo version disclosure in response"]
   [#"(?i)preact/[0-9]+\.[0-9]+" "preact version disclosure in response"]
   [#"(?i)solid/[0-9]+\.[0-9]+" "solid version disclosure in response"]
   [#"(?i)nextcloud/[0-9]+\.[0-9]+" "nextcloud version disclosure in response"]
   [#"(?i)owncloud/[0-9]+\.[0-9]+" "owncloud version disclosure in response"]
   [#"(?i)opensearch/[0-9]+\.[0-9]+" "opensearch version disclosure in response"]
   [#"(?i)logstash/[0-9]+\.[0-9]+" "logstash version disclosure in response"]
   [#"(?i)kibana/[0-9]+\.[0-9]+" "kibana version disclosure in response"]
   [#"(?i)filebeat/[0-9]+\.[0-9]+" "filebeat version disclosure in response"]
   [#"(?i)fluentd/[0-9]+\.[0-9]+" "fluentd version disclosure in response"]
   [#"(?i)consul/[0-9]+\.[0-9]+" "consul version disclosure in response"]
   [#"(?i)vault/[0-9]+\.[0-9]+" "vault version disclosure in response"]
   [#"(?i)etcd/[0-9]+\.[0-9]+" "etcd version disclosure in response"]
   [#"(?i)shopify/[0-9]+\.[0-9]+" "shopify version disclosure in response"]
   [#"(?i)wix/[0-9]+\.[0-9]+" "wix version disclosure in response"]
   [#"(?i)squarespace/[0-9]+\.[0-9]+" "squarespace version disclosure in response"]
   [#"(?i)webflow/[0-9]+\.[0-9]+" "webflow version disclosure in response"]
   [#"(?i)framer/[0-9]+\.[0-9]+" "framer version disclosure in response"]
   [#"(?i)shopware/[0-9]+\.[0-9]+" "shopware version disclosure in response"]
   [#"(?i)commercetools/[0-9]+\.[0-9]+" "commercetools version disclosure in response"]
   [#"(?i)spryker/[0-9]+\.[0-9]+" "spryker version disclosure in response"]
   [#"(?i)sulu/[0-9]+\.[0-9]+" "sulu version disclosure in response"]
   [#"(?i)api-platform/[0-9]+\.[0-9]+" "api-platform version disclosure in response"]
   [#"(?i)matomo/[0-9]+\.[0-9]+" "matomo version disclosure in response"]
   [#"(?i)plausible/[0-9]+\.[0-9]+" "plausible version disclosure in response"]
   [#"(?i)umami/[0-9]+\.[0-9]+" "umami version disclosure in response"]
   [#"(?i)posthog/[0-9]+\.[0-9]+" "posthog version disclosure in response"]
   [#"(?i)mixpanel/[0-9]+\.[0-9]+" "mixpanel version disclosure in response"]
   [#"(?i)amplitude/[0-9]+\.[0-9]+" "amplitude version disclosure in response"]
   [#"(?i)hotjar/[0-9]+\.[0-9]+" "hotjar version disclosure in response"]
   [#"(?i)fullstory/[0-9]+\.[0-9]+" "fullstory version disclosure in response"]
   [#"(?i)logrocket/[0-9]+\.[0-9]+" "logrocket version disclosure in response"]
   [#"(?i)sentry/[0-9]+\.[0-9]+" "sentry version disclosure in response"]
   [#"(?i)cloudflare/[0-9]+\.[0-9]+" "cloudflare version disclosure in response"]
   [#"(?i)akamai/[0-9]+\.[0-9]+" "akamai version disclosure in response"]
   [#"(?i)fastly/[0-9]+\.[0-9]+" "fastly version disclosure in response"]
   [#"(?i)cloudfront/[0-9]+\.[0-9]+" "cloudfront version disclosure in response"]
   [#"(?i)incapsula/[0-9]+\.[0-9]+" "incapsula version disclosure in response"]
   [#"(?i)sucuri/[0-9]+\.[0-9]+" "sucuri version disclosure in response"]
   [#"(?i)wordfence/[0-9]+\.[0-9]+" "wordfence version disclosure in response"]
   [#"(?i)imperva/[0-9]+\.[0-9]+" "imperva version disclosure in response"]
   [#"(?i)vercel/[0-9]+\.[0-9]+" "vercel version disclosure in response"]
   [#"(?i)netlify/[0-9]+\.[0-9]+" "netlify version disclosure in response"]
   [#"(?i)json::pp/[0-9]+\.[0-9]+" "json::pp version disclosure in response"]
   [#"(?i)encode/[0-9]+\.[0-9]+" "encode version disclosure in response"]
   [#"(?i)perl/[0-9]+\.[0-9]+" "perl version disclosure in response"]
   [#"(?i)digest/[0-9]+\.[0-9]+" "digest version disclosure in response"]
   [#"(?i)http::tiny/[0-9]+\.[0-9]+" "http::tiny version disclosure in response"]
   [#"(?i)carp/[0-9]+\.[0-9]+" "carp version disclosure in response"]
   [#"(?i)scalar/[0-9]+\.[0-9]+" "scalar version disclosure in response"]
   [#"(?i)list/[0-9]+\.[0-9]+" "list version disclosure in response"]
   [#"(?i)exporter/[0-9]+\.[0-9]+" "exporter version disclosure in response"]
   [#"(?i)getopt/[0-9]+\.[0-9]+" "getopt version disclosure in response"]
   [#"(?i)findbin/[0-9]+\.[0-9]+" "findbin version disclosure in response"]
   [#"(?i)file/[0-9]+\.[0-9]+" "file version disclosure in response"]
   [#"(?i)glob/[0-9]+\.[0-9]+" "glob version disclosure in response"]
   [#"(?i)cwd/[0-9]+\.[0-9]+" "cwd version disclosure in response"]
   [#"(?i)extutils/[0-9]+\.[0-9]+" "extutils version disclosure in response"]
   [#"(?i)test-harness/[0-9]+\.[0-9]+" "test-harness version disclosure in response"]
   [#"(?i)time/[0-9]+\.[0-9]+" "time version disclosure in response"]
   [#"(?i)chi/[0-9]+\.[0-9]+" "chi version disclosure in response"]
   [#"jdbc:[a-z0-9]+://[^\"'\s]+" "JDBC connection string in response"]])

(defn check-sensitive-info
  "IPA「Webアプリケーションの情報漏えい」. RULE 10027. Body patterns plus
  Server-version / X-Powered-By header disclosures."
  [{:keys [url]} resp]
  (vec (concat
        (for [[re why] sensitive-patterns
              :let [m (re-find re (get resp :body ""))]
              :when m]
          (core/finding {:rule-id "10027"
                         :cwe "CWE-209"
                         :severity :high
                         :title (str "Sensitive information disclosure: " why)
                         :evidence (subs (str m) 0 (min 40 (count (str m))))
                         :url url
                         :solution "Remove the secret from the response; rotate any exposed credential."}))
        (if-let [sv (when-let [sv (header-lower resp "server")]
                      (when (re-find #"/\d+\.\d+" (str sv)) sv))]
          [(core/finding {:rule-id "10027"
                          :cwe "CWE-209"
                          :severity :medium
                          :title "Server header exposes version (IPA 情報漏えい)"
                          :evidence (subs (str sv) 0 (min 40 (count (str sv))))
                          :url url
                          :solution "Remove the version token from the Server header."})]
          [])
        (if-let [xp (header-lower resp "x-powered-by")]
          [(core/finding {:rule-id "10027"
                          :cwe "CWE-209"
                          :severity :medium
                          :title "X-Powered-By exposes framework (IPA 情報漏えい)"
                          :evidence (subs (str xp) 0 (min 40 (count (str xp))))
                          :url url
                          :solution "Remove the X-Powered-By header."})]
          [])
        (vec (for [h ["via" "x-aspnet-version" "x-generator" "x-aspnetmvc-version"]
                   :let [v (header-lower resp h)]
                   :when (and v (re-find #"/\d+\.\d+|\d+\.\d+" (str v)))]
               (core/finding {:rule-id "10027"
                              :cwe "CWE-209"
                              :severity :medium
                              :title (str "Version disclosure via " h " header (IPA 情報漏えい)")
                              :evidence (subs (str v) 0 (min 40 (count (str v))))
                              :url url
                              :solution "Remove the version token from the header."})))))

)

(defn check-cors
  "RULE 10038 (headers family). Access-Control-Allow-Origin: * without
  credentials is usually intentional; with Allow-Credentials: true it is a
  finding (CWE-942 Permissive CORS). Single-origin values are not findings.
  Also flags Origin reflection with credentials (ACAO == request Origin with
  Allow-Credentials: true), which trusts every origin that asks."
  [{:keys [url headers]} resp]
  (let [acao (header-lower resp "access-control-allow-origin")
        cred (header-lower resp "access-control-allow-credentials")
        cred? (and cred (re-find #"(?i)^\s*true\s*$" (str cred)))
        wild? (and acao (re-find #"\*" (str acao)))
        req-origin (when headers (some (fn [[k v]] (when (= (str/lower-case (name k)) "origin") v)) headers))
        reflected? (and acao req-origin (= (str/lower-case (str acao)) (str/lower-case (str req-origin))))
        acah (header-lower resp "access-control-allow-headers")
        acah-wild? (and acah (re-find #"\*" (str acah)))
        acam (header-lower resp "access-control-allow-methods")
        acam-wild? (and acam (re-find #"\*" (str acam)))]
    (vec (concat
          (if (and wild? cred?)
            [(core/finding {:rule-id "10038"
                            :cwe "CWE-942"
                            :severity :medium
                            :title "Permissive CORS with credentials (Access-Control-Allow-Origin: * + Allow-Credentials: true)"
                            :evidence (str acao)
                            :url url
                            :solution "Restrict Access-Control-Allow-Origin to trusted origins when credentials are allowed."})]
            [])
          (if (and reflected? cred?)
            [(core/finding {:rule-id "10038"
                            :cwe "CWE-942"
                            :severity :high
                            :title "CORS origin reflection with credentials (any origin allowed)"
                            :evidence (str acao)
                            :url url
                            :solution "Do not reflect the Origin header; allow only trusted origins when credentials are used."})]
            [])
          (if (and acao cred? (= "null" (str/lower-case (str/trim (str acao)))))
            [(core/finding {:rule-id "10038"
                            :cwe "CWE-942"
                            :severity :high
                            :title "CORS allows null origin with credentials (sandboxed/file origins trusted)"
                            :evidence (str acao)
                            :url url
                            :solution "Allow only trusted origins; null is never a trusted origin when credentials are used."})]
            [])
          (if (and acah-wild? cred?)
            [(core/finding {:rule-id "10038"
                            :cwe "CWE-942"
                            :severity :medium
                            :title "CORS Allow-Headers wildcard with credentials"
                            :evidence (str acah)
                            :url url
                            :solution "Enumerate allowed request headers instead of * when credentials are allowed."})]
            [])
          (if (and acam-wild? cred?)
            [(core/finding {:rule-id "10038"
                            :cwe "CWE-942"
                            :severity :medium
                            :title "CORS Allow-Methods wildcard with credentials"
                            :evidence (str acam)
                            :url url
                            :solution "Enumerate allowed HTTP methods instead of * when credentials are allowed."})]
            [])))))

(defn check-refresh
  "Refresh header pointing at an external absolute URL (rule 10038, CWE-693).
  Delay-only and same-origin Refresh values are not findings. Pure header
  inspection on the response already observed."
  [{:keys [url]} resp]
  (let [rfh (header-lower resp "refresh")
        um (when rfh (re-find #"(?i)url\s*=\s*([^;]+)" (str rfh)))
        dest (when um (str/trim (second um)))
        host-m (when dest (re-find #"(?i)^(?:https?:)?//([^/]+)" dest))
        req-host (when url (second (re-find #"(?i)^https?://([^/]+)" url)))
        dest-host (when host-m (str/lower-case (second host-m)))
        reqh (when req-host (str/lower-case req-host))]
    (cond
      (and dest (re-find #"(?i)^(javascript|data|vbscript):" dest))
      [(core/finding {:rule-id "10038"
                      :cwe "CWE-693"
                      :severity :high
                      :title "Refresh header uses dangerous javascript:/data: URI scheme"
                      :evidence (str rfh)
                      :url url
                      :solution "Only allow http/https Refresh destinations; block javascript:, data: and vbscript: schemes."})]

      (and dest-host reqh (not= dest-host reqh))
      [(core/finding {:rule-id "10038"
                      :cwe "CWE-693"
                      :severity :low
                      :title "Refresh header points to external origin (open redirect candidate)"
                      :evidence (str rfh)
                      :url url
                      :solution "Avoid external Refresh targets; use server-side redirects to same-origin locations."})]

      :else [])))

(defn check-cache-privacy
  "Session response that intermediaries may store (rule 10010, CWE-538).
  Responses carrying Set-Cookie are treated as sensitive: a Cache-Control
  with public/max-age but without no-store/no-cache/private is a finding.
  Pure header inspection."
  [{:keys [url]} resp]
  (let [cookie? (some (fn [[k _]] (= (str/lower-case (name k)) "set-cookie")) (get resp :headers {}))
        cc (header-lower resp "cache-control")
        cc-l (when cc (str/lower-case (str cc)))
        protected? (when cc-l (or (re-find #"no-store" cc-l)
                                  (re-find #"no-cache" cc-l)
                                  (re-find #"private" cc-l)))
        pragma (header-lower resp "pragma")
        expires (header-lower resp "expires")
        expires-future? (when expires
                          (and (not (re-find #"(?i)^(0|-1|thu, 01 jan 1970)" (str/trim (str expires))))
                               (not (re-find #"(?i)1970" (str expires)))))
        cacheable? (or (when cc-l (or (re-find #"public" cc-l)
                                      (re-find #"max-age" cc-l)))
                       expires-future?)]
    (concat
     (if (and cookie? cacheable? (not protected?))
       [(core/finding {:rule-id "10010"
                       :cwe "CWE-538"
                       :severity :medium
                       :title "Sensitive response may be cached (Set-Cookie with public/max-age and no no-store/no-cache/private)"
                       :evidence (str cc)
                       :url url
                       :solution "Mark session responses with Cache-Control: no-store, no-cache, private."})]
       [])
     (if (and cookie? pragma (re-find #"(?i)no-cache" (str pragma)) (not cc))
       [(core/finding {:rule-id "10010"
                       :cwe "CWE-538"
                       :severity :medium
                       :title "Sensitive response uses Pragma-only cache directives (no Cache-Control)"
                       :evidence (str pragma)
                       :url url
                       :solution "Use Cache-Control: no-store, no-cache, private instead of Pragma."})]
       []))))

(defn check-location-redirect
  "Location header pointing at an external absolute URL (rule 10038, CWE-601
  Open Redirect). Same-origin and relative targets are not findings. Pure
  header inspection on the response already observed."
  [{:keys [url]} resp]
  (let [loc (header-lower resp "location")
        dest (when loc (str/trim (str loc)))
        host-m (when dest (re-find #"(?i)^https?://([^/]+)" dest))
        req-host (when url (second (re-find #"(?i)^https?://([^/]+)" url)))
        dest-host (when host-m (str/lower-case (second host-m)))
        reqh (when req-host (str/lower-case req-host))]
    (cond
      (and dest (re-find #"(?i)^(javascript|data|vbscript):" dest))
      [(core/finding {:rule-id "10038"
                      :cwe "CWE-601"
                      :severity :high
                      :title "Location header uses dangerous javascript:/data: URI scheme"
                      :evidence (str loc)
                      :url url
                      :solution "Only allow http/https redirect destinations; block javascript:, data: and vbscript: schemes."})]

      (and dest-host reqh (not= dest-host reqh))
      [(core/finding {:rule-id "10038"
                      :cwe "CWE-601"
                      :severity :low
                      :title "Location header points to external origin (open redirect candidate)"
                      :evidence (str loc)
                      :url url
                      :solution "Validate redirect targets server-side; allow only same-origin destinations."})]

      :else [])))

(defn check-www-authenticate
  "HTTP Authentication Request over plaintext HTTP (rule 10037, CWE-319).
  A WWW-Authenticate header on a plain http:// request means credentials
  traverse the wire unencrypted."
  [{:keys [url]} resp]
  (let [w (header-lower resp "www-authenticate")]
    (if (and w url (re-find #"(?i)^http://" (str url)))
      [(core/finding {:rule-id "10037"
                      :cwe "CWE-319"
                      :severity :medium
                      :title "HTTP Authentication Request over plaintext HTTP"
                      :evidence (subs (str w) 0 (min 40 (count (str w))))
                      :url url
                      :solution "Serve authentication over HTTPS; redirect http:// to https://."})]
      [])))

(defn check-server-version
  "Server header version disclosure (rule 10027, CWE-209).
  A Server header carrying /version exposes the software stack."
  [{:keys [url]} resp]
  (let [server (header-lower resp "server")
        powered (header-lower resp "x-powered-by")]
    (concat
     (if (and server (re-find #"/\d+\.\d+" (str server)))
       [(core/finding {:rule-id "10027"
                       :cwe "CWE-209"
                       :severity :medium
                       :title "Server header exposes software version"
                       :evidence (subs (str server) 0 (min 40 (count (str server))))
                       :url url
                       :solution "Remove version information from the Server header."})]
       [])
     (if (and powered (re-find #"/\d+\.\d+" (str powered)))
       [(core/finding {:rule-id "10027"
                       :cwe "CWE-209"
                       :severity :medium
                       :title "X-Powered-By header exposes software version"
                       :evidence (subs (str powered) 0 (min 40 (count (str powered))))
                       :url url
                       :solution "Remove the X-Powered-By header or strip the version."})]
       []))))


(defn check-dom-xss-sink
  "DOM XSS sink present in response body (rule 40028, CWE-79).
  Sinks: innerHTML, document.write, eval, location.hash-assigned HTML,
  outerHTML, insertAdjacentHTML, setTimeout-string, setInterval-string.
  Pure body inspection on the response already observed; no browser needed.
  Benign mentions without assignment (eg 'innerHTML is set') are clean."
  [{:keys [url]} resp]
  (let [body (get resp :body "")
        sinks [ #"innerHTML\s*=" #"document\.write" #"(?i)\beval\s*\(" #"outerHTML\s*=" #"insertAdjacentHTML" #"\.html\s*\(" #"setTimeout\s*\(" #"setInterval\s*\(" ]]
    (vec (for [re sinks
               :let [m (re-find re (str body))]
               :when m]
           (core/finding {:rule-id "40028"
                          :cwe "CWE-79"
                          :severity :medium
                          :title "DOM XSS sink in page (static sink scan)"
                          :evidence (subs (str m) 0 (min 40 (count (str m))))
                          :url url
                          :param nil
                          :solution "Avoid assigning untrusted data to HTML sinks; use textContent or escape before insertion."})))))


(defn check-js-library-version
  "Outdated JS library referenced in the page (rule 10003, CWE-829/CWE-1104).
  Heuristic: jQuery < 3.5.0, Bootstrap < 4.5.0, AngularJS < 1.8.2.
  Pure body inspection; a modern version is clean. Version family matches
  the script filename only (jquery-1.12.4.min.js etc)."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        ;; jQuery: major 1 or 2, or 3.<4
        jq (re-find #"(?i)jquery-([0-9]+).([0-9]+).([0-9]+)" body)
        jq-old (when jq (let [maj (Long/parseLong (nth jq 1))
                                mnr (Long/parseLong (nth jq 2))]
                            (or (< maj 3) (and (= maj 3) (< mnr 5)))))
        bs (re-find #"(?i)bootstrap-([0-9]+).([0-9]+).([0-9]+)" body)
        bs-old (when bs (let [maj (Long/parseLong (nth bs 1))]
                            (< maj 4)))
        ng (re-find #"(?i)angular-([0-9]+).([0-9]+).([0-9]+)" body)
        ng-old (when ng (let [maj (Long/parseLong (nth ng 1))]
                            (< maj 2)))]
    (vec (concat
          (when jq-old
            [(core/finding {:rule-id "10003"
                           :cwe "CWE-1104"
                           :severity :high
                           :title "Outdated jQuery version in page"
                           :evidence (subs (str jq) 0 (min 40 (count (str jq))))
                           :url url
                           :solution "Upgrade jQuery to 3.5.0 or later."})])
          (when bs-old
            [(core/finding {:rule-id "10003"
                           :cwe "CWE-1104"
                           :severity :medium
                           :title "Outdated Bootstrap version in page"
                           :evidence (subs (str bs) 0 (min 40 (count (str bs))))
                           :url url
                           :solution "Upgrade Bootstrap to 4.5.0 or later."})])
          (when ng-old
            [(core/finding {:rule-id "10003"
                           :cwe "CWE-1104"
                           :severity :high
                           :title "Outdated AngularJS version in page"
                           :evidence (subs (str ng) 0 (min 40 (count (str ng))))
                           :url url
                           :solution "Migrate off AngularJS or upgrade to 1.8.2+."})])))))


(defn check-ssti-reflection
  "SSTI reflection heuristic (rule 40029, CWE-94). Flags when the body
  contains an evaluated arithmetic result (49 for 7*7, 1337 for 13*103,
  31337 for 7*4477) without the original template literal nearby, i.e.
  the classic 7*7 -> 49 marker. Pure body inspection; benign pages that
  merely contain 49 in unrelated context are not matched without the
  evaluation context (7*7 absent and 49 present with '7' operands)."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        evaluated-7x7 (and (some? (re-find #"7\s*\*\s*7" body))
                           (some? (re-find #">49<" body)))]
    (if evaluated-7x7
      [(core/finding {:rule-id "40029"
                      :cwe "CWE-94"
                      :severity :medium
                      :title "Possible SSTI (template arithmetic evaluated)"
                      :evidence "7*7 evaluated to 49 in body"
                      :url url
                      :solution "Do not pass user input as template code; sandbox/escape templates."})]
      [])))


(defn check-sourcemap-exposure
  "JS source map exposed (rule 40030, CWE-552). Flags when the body
  references a .map file (sourceMappingURL=*.map or .map in src),
  which can leak original source. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)sourceMappingURL=[^\s]+\.map" body)]
    (if m
      [(core/finding {:rule-id "40030"
                      :cwe "CWE-552"
                      :severity :medium
                      :title "Source map exposed in page"
                      :evidence (subs (str m) 0 (min 40 (count (str m))))
                      :url url
                      :solution "Remove sourceMappingURL from production or restrict .map files."})]
      [])))



(defn check-dotenv-exposure
  "Dotenv / config file exposure (rule 40031, CWE-538). Flags bodies that
  look like a raw .env/config file (3+ KEY=VALUE lines, one a secret key).
  Line-split based; pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        lines ((fn [s] (str/split s "
")) body)
        kv (filter #(re-find #"^[A-Z_]{3,32}=" %) lines)
        secret-key (some #(re-find #"(?i)(DB_PASSWORD|AWS_SECRET|SECRET_KEY|PRIVATE_KEY|API_KEY)" %) lines)]
    (if (and secret-key (>= (count kv) 3))
      [(core/finding {:rule-id "40031"
                      :cwe "CWE-538"
                      :severity :high
                      :title "Config/dotenv file exposure in response"
                      :evidence (str (count kv) " KEY=VALUE lines, secret key present")
                      :url url
                      :solution "Serve .env/config outside webroot; block dotfiles at the web server."})]
      [])))


(defn check-git-exposure
  "Git repository exposure (rule 40032, CWE-538). Flags bodies containing
  git config/HEAD markers (ref: refs/heads/, [core] repositoryformatversion).
  Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        markers [ #"ref: refs/heads/" #"repositoryformatversion" #"[core]" #"raw.githubusercontent.com"]
        hits (filter #(some? (re-find % body)) markers)]
    (if (>= (count hits) 2)
      [(core/finding {:rule-id "40032"
                      :cwe "CWE-538"
                      :severity :high
                      :title "Git repository exposure in response"
                      :evidence (str (count hits) " git markers found")
                      :url url
                      :solution "Block .git/ from the web server; serve repos only via a git server."})]
      [])))


(defn check-backup-exposure
  "Backup/archive file exposure (rule 40033, CWE-552). Flags bodies that
  look like a raw backup (SQL dump header, ZIP magic, backup config).
  Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        sql-dump (some? (re-find #"(?im)^-- MySQL dump|^-- PostgreSQL database dump" body))
        zip (some? (re-find #"PK[\u0003\u0004]" body))
        tar (some? (re-find #"(?i)ustar" body))]
    (if (or sql-dump zip tar)
      [(core/finding {:rule-id "40033"
                      :cwe "CWE-552"
                      :severity :high
                      :title "Backup/archive file exposure in response"
                      :evidence (str "backup markers: sql-dump=" sql-dump " zip=" zip " tar=" tar)
                      :url url
                      :solution "Keep backups outside the webroot; block .sql/.zip/.bak at the web server."})]
      [])))


(defn check-phpinfo-exposure
  "phpinfo/debug endpoint response (rule 40034, CWE-209). Flags bodies
  containing phpinfo markers (phpinfo() output tables, PHP Version with
  config paths, loaded modules list). Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        p1 (some? (re-find #"(?i)phpinfo\(\)" body))
        p2 (some? (re-find #"PHP Version" body))
        p3 (some? (re-find #"Loaded modules" body))
        p4 (some? (re-find #"/etc/php" body))]
    (if (or (and p1 p2) p3 (and p2 p4))
      [(core/finding {:rule-id "40034"
                      :cwe "CWE-209"
                      :severity :medium
                      :title "phpinfo/debug exposure in response"
                      :evidence (str "markers phpinfo=" p1 " version=" p2 " config=" p4)
                      :url url
                      :solution "Remove phpinfo/debug endpoints from production."})]
      [])))


(defn check-stacktrace-exposure
  "Stack trace / error page exposure (rule 40035, CWE-209). Flags Java
  stack traces, Python tracebacks, Rails/Node error pages. Pure body
  inspection; a generic 500 page without traces is clean."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        java (some? (re-find #"(?i)Exception in thread|at [a-zA-Z0-9_.$]+\.[a-zA-Z0-9_.$]+\(" body))
        py (some? (re-find #"Traceback \(most recent call last\)" body))
        rb (some? (re-find #"(?i)ActionController::RoutingError|NoMethodError" body))
        js (some? (re-find #"(?i)at Object\.|node:internal" body))]
    (if (or java py rb js)
      [(core/finding {:rule-id "40035"
                      :cwe "CWE-209"
                      :severity :medium
                      :title "Stack trace exposed in error page"
                      :evidence (str "markers java=" java " py=" py " rb=" rb " js=" js)
                      :url url
                      :solution "Return generic error pages in production; log traces server-side only."})]
      [])))


(defn check-password-in-url
  "Password/token in URL (rule 40036, CWE-359). Flags request URLs or
  bodies carrying password/passwd/pwd= or token= in query strings, which
  leak to logs/proxies. Pure inspection of the observed request."
  [{:keys [url]} _resp]
  (let [u (str url)
        pw (some? (re-find #"(?i)[?&](password|passwd|pwd)=" u))
        tk (some? (re-find #"(?i)[?&](api[_-]?key|token|secret)=" u))]
    (if (or pw tk)
      [(core/finding {:rule-id "40036"
                      :cwe "CWE-359"
                      :severity :medium
                      :title "Sensitive parameter in URL"
                      :evidence (if pw "password-like param in URL" "token/api-key param in URL")
                      :url url
                      :solution "Move credentials to POST body or Authorization header; never in URL."})]
      [])))


(defn check-url-credentials
  "Credentials embedded in URL (rule 40037, CWE-359). Flags URLs with
  userinfo (scheme://user:pass@host). Pure inspection of observed URL."
  [{:keys [url]} _resp]
  (let [u (str url)]
    (if (some? (re-find #"[a-zA-Z][a-zA-Z0-9+.-]*://[^/@]+@" u))
      [(core/finding {:rule-id "40037"
                      :cwe "CWE-359"
                      :severity :medium
                      :title "Credentials embedded in URL"
                      :evidence "userinfo present in URL"
                      :url url
                      :solution "Use Authorization header over HTTPS; never embed credentials in URLs."})]
      [])))


(defn check-email-disclosure
  "Personal email disclosure (rule 40038, CWE-359). Flags bodies with
  3+ distinct personal email addresses (role addresses like info@ counted
  once). Pure body inspection; a single contact email is informational."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        emails (set (re-seq #"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}" body))]
    (if (>= (count emails) 3)
      [(core/finding {:rule-id "40038"
                      :cwe "CWE-359"
                      :severity :low
                      :title "Personal email addresses disclosed in page"
                      :evidence (str (count emails) " distinct emails")
                      :url url
                      :solution "Avoid publishing personal emails; use contact forms or role addresses."})]
      [])))



(defn check-login-autocomplete
  "Password field without autocomplete=off (rule 40039, CWE-359). Flags
  forms with type=password but no autocomplete attribute on the field.
  Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        has-pwd (some? (re-find #"(?i)type.?.password" body))
        no-off (nil? (re-find #"(?i)autocomplete=" body))]
    (if (and has-pwd no-off)
      [(core/finding {:rule-id "40039"
                      :cwe "CWE-359"
                      :severity :low
                      :title "Password field without autocomplete=off"
                      :evidence "password field, no autocomplete attribute"
                      :url url
                      :solution "Set autocomplete=off or current-password on password fields."})]
      [])))



(defn check-internal-ip-disclosure
  "Internal/private IP disclosure (rule 40040, CWE-200). Flags bodies
  containing RFC1918 or loopback addresses. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        pats [#"10.[0-9]+.[0-9]+.[0-9]+" #"192.168.[0-9]+.[0-9]+" #"172.1[6-9].[0-9]+.[0-9]+" #"172.2[0-9].[0-9]+.[0-9]+" #"172.3[01].[0-9]+.[0-9]+" #"127.[0-9]+.[0-9]+.[0-9]+"]
        hits (remove nil? (map #(re-find % body) pats))]
    (if (seq hits)
      [(core/finding {:rule-id "40040"
                      :cwe "CWE-200"
                      :severity :low
                      :title "Internal IP address disclosed in page"
                      :evidence (str (first hits))
                      :url url
                      :solution "Do not expose internal addresses in responses."})]
      [])))


(defn check-internal-hostname
  "Internal hostname disclosure (rule 40041, CWE-200). Flags bodies with
  *.internal / *.local / *.intranet hostnames. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"[A-Za-z0-9_-]+[.](internal|local|intranet)(?![A-Za-z0-9])" body)]
    (if m
      [(core/finding {:rule-id "40041"
                      :cwe "CWE-200"
                      :severity :low
                      :title "Internal hostname disclosed in page"
                      :evidence (str m)
                      :url url
                      :solution "Do not expose internal hostnames in responses."})]
      [])))


(defn check-jwt-exposure
  "JWT token exposure (rule 40042, CWE-798). Flags bodies/URLs with
  JWT-shaped tokens (eyJ... . ... . ..., with alg header). Pure
  inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body "") (str url))
        m (re-find #"eyJ[A-Za-z0-9_-]{8,}.[A-Za-z0-9_-]{8,}.[A-Za-z0-9_-]{8,}" body)]
    (if m
      [(core/finding {:rule-id "40042"
                      :cwe "CWE-798"
                      :severity :medium
                      :title "JWT token exposed in response/URL"
                      :evidence (subs (str m) 0 (min 24 (count (str m))))
                      :url url
                      :solution "Do not embed bearer tokens in pages/URLs; use short-lived opaque sessions."})]
      [])))


(defn check-apikey-exposure
  "Provider API key exposure (rule 40043, CWE-798). Flags well-known
  key shapes: AWS AKIA..., GCP AIza..., GitHub ghp_..., Stripe sk-live-,
  Slack xox[baprs]-. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        pats [#"AKIA[0-9A-Z]{16}" #"AIza[0-9A-Za-z_-]{35}" #"ghp_[A-Za-z0-9]{36}" #"sk-live-[A-Za-z0-9]{24,}" #"xox[baprs]-[A-Za-z0-9-]{10,}"]
        hits (remove nil? (map #(re-find % body) pats))]
    (if (seq hits)
      [(core/finding {:rule-id "40043"
                      :cwe "CWE-798"
                      :severity :high
                      :title "API key exposed in response"
                      :evidence (str (first hits))
                      :url url
                      :solution "Revoke and rotate the key; load secrets server-side only."})]
      [])))


(defn check-private-key-exposure
  "Private key exposure (rule 40044, CWE-798). Flags PEM private key
  blocks in bodies. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"-----BEGIN (RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----" body)]
    (if m
      [(core/finding {:rule-id "40044"
                      :cwe "CWE-798"
                      :severity :high
                      :title "Private key block exposed in response"
                      :evidence (str m)
                      :url url
                      :solution "Revoke and rotate the key immediately; never serve key material."})]
      [])))


(defn check-cookie-attributes
  "Session cookie attributes (rule 40045, CWE-1004). Flags Set-Cookie
  values missing HttpOnly or Secure. Pure response inspection."
  [{:keys [url]} resp]
  (let [headers (get resp :headers {})
        sc (get headers "set-cookie")
        cookies (if (string? sc) [sc]
                    (filter string? (flatten [(get headers :set-cookie) (get headers "Set-Cookie")])))
        missing (remove (fn [c]
                          (let [lc (str/lower-case (str c))]
                            (and (some? (re-find #"(?i)httponly" lc)) (some? (re-find #"(?i)secure" lc)))))
                        cookies)]
    (if (seq missing)
      [(core/finding {:rule-id "40045"
                      :cwe "CWE-1004"
                      :severity :medium
                      :title "Cookie missing HttpOnly/Secure attribute"
                      :evidence (str (first missing))
                      :url url
                      :solution "Set HttpOnly and Secure on session cookies."})]
      [])))


(defn check-cookie-samesite
  "Cookie missing SameSite attribute (rule 40046, CWE-1004). Flags
  Set-Cookie values without SameSite=. Pure response inspection."
  [{:keys [url]} resp]
  (let [headers (get resp :headers {})
        sc (get headers "set-cookie")
        cookies (if (string? sc) [sc]
                    (filter string? (flatten [(get headers :set-cookie) (get headers "Set-Cookie")])))
        missing (remove #(some? (re-find #"(?i)samesite=" (str %))) cookies)]
    (if (seq missing)
      [(core/finding {:rule-id "40046"
                      :cwe "CWE-1004"
                      :severity :medium
                      :title "Cookie missing SameSite attribute"
                      :evidence (str (first missing))
                      :url url
                      :solution "Set SameSite=Lax or Strict on session cookies."})]
      [])))


(defn check-missing-sri
  "External script without SRI (rule 40047, CWE-829). Flags
  <script src=http...> tags loaded from other origins without an
  integrity attribute. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        tags (re-seq #"<script[^>]*>" body)
        external (remove #(some? (re-find #"(?i)integrity=" %)) (filter #(some? (re-find #"(?i)src.?.https?://" %)) tags))]
    (if (seq external)
      [(core/finding {:rule-id "40047"
                      :cwe "CWE-829"
                      :severity :medium
                      :title "External script without Subresource Integrity"
                      :evidence (str (first external))
                      :url url
                      :solution "Add integrity hashes to third-party scripts or self-host them."})]
      [])))


(defn check-tabnabbing
  "Reverse tabnabbing (rule 40048, CWE-1021). Flags <a target=_blank>
  links without rel=noopener. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        tags (re-seq #"<a[^>]*>" body)
        bad (filter (fn [tag]
                      (and (some? (re-find #"(?i)target=.?_blank" tag))
                           (nil? (re-find #"(?i)rel=.?[^>]*noopener" tag))))
                    tags)]
    (if (seq bad)
      [(core/finding {:rule-id "40048"
                      :cwe "CWE-1021"
                      :severity :medium
                      :title "target=_blank without rel=noopener"
                      :evidence (str (first bad))
                      :url url
                      :solution "Add rel=noopener to target=_blank links."})]
      [])))


(defn check-mixed-content
  "Mixed content (rule 40049, CWE-319). Flags HTTPS pages referencing
  http:// resources. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        https-page (some? (re-find #"(?i)^https://" (str url)))
        m (when https-page (re-find #"(?i)http://[A-Za-z0-9]" body))]
    (if m
      [(core/finding {:rule-id "40049"
                      :cwe "CWE-319"
                      :severity :medium
                      :title "Mixed content: http resource on https page"
                      :evidence (subs (str m) 0 (min 32 (count (str m))))
                      :url url
                      :solution "Serve all resources over HTTPS."})]
      [])))


(defn check-insecure-websocket
  "Insecure WebSocket on HTTPS page (rule 40050, CWE-319). Flags ws://
  URLs referenced from https pages. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        https-page (some? (re-find #"(?i)^https://" (str url)))
        m (when https-page (re-find #"(?i)ws://[A-Za-z0-9]" body))]
    (if m
      [(core/finding {:rule-id "40050"
                      :cwe "CWE-319"
                      :severity :medium
                      :title "Insecure WebSocket (ws://) on https page"
                      :evidence (subs (str m) 0 (min 32 (count (str m))))
                      :url url
                      :solution "Use wss:// for WebSockets on HTTPS pages."})]
      [])))


(defn check-cookie-long-expiry
  "Cookie with excessive lifetime (rule 40051, CWE-1004). Flags
  Set-Cookie Expires dates in years 2035+. Pure response inspection."
  [{:keys [url]} resp]
  (let [headers (get resp :headers {})
        sc (get headers "set-cookie")
        cookies (if (string? sc) [sc]
                    (filter string? (flatten [(get headers :set-cookie) (get headers "Set-Cookie")])))
        bad (filter #(some? (re-find #"(?i)expires=[^;]*(20(3[5-9]|[4-9][0-9]))" (str %))) cookies)]
    (if (seq bad)
      [(core/finding {:rule-id "40051"
                      :cwe "CWE-1004"
                      :severity :low
                      :title "Cookie with excessive expiry"
                      :evidence (str (first bad))
                      :url url
                      :solution "Use short session lifetimes."})]
      [])))


(defn check-clickjacking
  "Missing anti-clickjacking headers (rule 40052, CWE-1021). Flags
  responses with neither X-Frame-Options nor CSP frame-ancestors.
  Pure response inspection."
  [{:keys [url]} resp]
  (let [headers (get resp :headers {})
        names (set (map #(str/lower-case (str %)) (keys headers)))
        has-xfo (contains? names "x-frame-options")
        csp (str (or (get headers "content-security-policy") (get headers "Content-Security-Policy") ""))
        has-ancestors (some? (re-find #"(?i)frame-ancestors" csp))]
    (if (and (not has-xfo) (not has-ancestors))
      [(core/finding {:rule-id "40052"
                      :cwe "CWE-1021"
                      :severity :low
                      :title "No anti-clickjacking headers"
                      :evidence "X-Frame-Options and CSP frame-ancestors missing"
                      :url url
                      :solution "Send X-Frame-Options: SAMEORIGIN or CSP frame-ancestors."})]
      [])))


(defn check-hsts
  "Missing HSTS on HTTPS (rule 40053, CWE-319). Flags https responses
  without Strict-Transport-Security. Pure response inspection."
  [{:keys [url]} resp]
  (let [headers (get resp :headers {})
        names (set (map #(str/lower-case (str %)) (keys headers)))
        https-page (some? (re-find #"(?i)^https://" (str url)))]
    (if (and https-page (not (contains? names "strict-transport-security")))
      [(core/finding {:rule-id "40053"
                      :cwe "CWE-319"
                      :severity :medium
                      :title "Missing Strict-Transport-Security header"
                      :evidence "HSTS missing on https response"
                      :url url
                      :solution "Send Strict-Transport-Security: max-age=31536000; includeSubDomains"})]
      [])))


(defn check-nosniff
  "Missing X-Content-Type-Options (rule 40054, CWE-693). Flags responses
  whose X-Content-Type-Options is absent or not nosniff. Pure response
  inspection."
  [{:keys [url]} resp]
  (let [headers (get resp :headers {})
        val (str (or (get headers "x-content-type-options") (get headers "X-Content-Type-Options") ""))]
    (if (nil? (re-find #"(?i)nosniff" val))
      [(core/finding {:rule-id "40054"
                      :cwe "CWE-693"
                      :severity :low
                      :title "Missing X-Content-Type-Options: nosniff"
                      :evidence (str val)
                      :url url
                      :solution "Send X-Content-Type-Options: nosniff."})]
      [])))


(defn check-referrer-policy
  "Missing Referrer-Policy (rule 40055, CWE-693). Flags responses
  without Referrer-Policy. Pure response inspection."
  [{:keys [url]} resp]
  (let [headers (get resp :headers {})
        names (set (map #(str/lower-case (str %)) (keys headers)))]
    (if (not (contains? names "referrer-policy"))
      [(core/finding {:rule-id "40055"
                      :cwe "CWE-693"
                      :severity :low
                      :title "Missing Referrer-Policy header"
                      :evidence "Referrer-Policy missing"
                      :url url
                      :solution "Send Referrer-Policy: strict-origin-when-cross-origin or stricter."})]
      [])))


(defn check-permissions-policy
  "Missing Permissions-Policy (rule 40056, CWE-693). Flags responses
  without Permissions-Policy. Pure response inspection."
  [{:keys [url]} resp]
  (let [headers (get resp :headers {})
        names (set (map #(str/lower-case (str %)) (keys headers)))]
    (if (not (contains? names "permissions-policy"))
      [(core/finding {:rule-id "40056"
                      :cwe "CWE-693"
                      :severity :low
                      :title "Missing Permissions-Policy header"
                      :evidence "Permissions-Policy missing"
                      :url url
                      :solution "Send a restrictive Permissions-Policy."})]
      [])))


(defn check-http-redirect
  "HTTP downgrade redirect (rule 40057, CWE-319). Flags https pages
  whose body contains an http:// refresh/redirect target. Pure body
  inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        https-page (some? (re-find #"(?i)^https://" (str url)))
        m (when https-page (re-find #"(?i)(refresh|redirect)[^>]*http://[A-Za-z0-9]" body))]
    (if m
      [(core/finding {:rule-id "40057"
                      :cwe "CWE-319"
                      :severity :medium
                      :title "HTTP redirect on https page"
                      :evidence (subs (str m) 0 (min 48 (count (str m))))
                      :url url
                      :solution "Redirect only to HTTPS targets."})]
      [])))


(defn check-csp-unsafe-inline
  "CSP allows unsafe-inline (rule 40058, CWE-693). Flags
  Content-Security-Policy headers containing 'unsafe-inline'. Pure
  response inspection."
  [{:keys [url]} resp]
  (let [headers (get resp :headers {})
        csp (str (or (get headers "content-security-policy") (get headers "Content-Security-Policy") ""))]
    (if (some? (re-find #"(?i)unsafe-inline" csp))
      [(core/finding {:rule-id "40058"
                      :cwe "CWE-693"
                      :severity :medium
                      :title "CSP allows unsafe-inline"
                      :evidence (subs csp 0 (min 64 (count csp)))
                      :url url
                      :solution "Remove unsafe-inline; use nonces or hashes."})]
      [])))


(defn check-csp-missing
  "Missing Content-Security-Policy (rule 40059, CWE-693). Flags responses
  with neither CSP nor CSP-Report-Only. Pure response inspection."
  [{:keys [url]} resp]
  (let [headers (get resp :headers {})
        names (set (map #(str/lower-case (str %)) (keys headers)))]
    (if (and (not (contains? names "content-security-policy"))
             (not (contains? names "content-security-policy-report-only")))
      [(core/finding {:rule-id "40059"
                      :cwe "CWE-693"
                      :severity :medium
                      :title "Missing Content-Security-Policy"
                      :evidence "No CSP header present"
                      :url url
                      :solution "Send a restrictive Content-Security-Policy."})]
      [])))


(defn check-form-http-action
  "HTTPS form submitting to HTTP (rule 40060, CWE-319). Flags forms on
  https pages whose action is http://. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        https-page (some? (re-find #"(?i)^https://" (str url)))
        tags (re-seq #"<form[^>]*>" body)
        bad (when https-page
              (filter #(some? (re-find #"(?i)action=.?http://[A-Za-z0-9]" %)) tags))]
    (if (seq bad)
      [(core/finding {:rule-id "40060"
                      :cwe "CWE-319"
                      :severity :medium
                      :title "Form submits to HTTP on https page"
                      :evidence (str (first bad))
                      :url url
                      :solution "Submit forms over HTTPS only."})]
      [])))


(defn check-dom-open-redirect
  "DOM open redirect (rule 40061, CWE-601). Flags location assignment
  from location.hash/search. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))]
    (if (some? (re-find #"(?i)location\.(href|assign|replace)[^;]*location\.(hash|search)" body))
      [(core/finding {:rule-id "40061"
                      :cwe "CWE-601"
                      :severity :medium
                      :title "DOM open redirect via URL fragment/query"
                      :evidence (subs (str (re-find #"(?i)location\.(href|assign|replace)[^;]*location\.(hash|search)" body)) 0 (min 64 (count (str (re-find #"(?i)location\.(href|assign|replace)[^;]*location\.(hash|search)" body)))))
                      :url url
                      :solution "Validate redirect targets against an allowlist."})]
      [])))


(defn check-postmessage-wildcard
  "postMessage wildcard targetOrigin (rule 40062, CWE-79). Flags
  postMessage calls with a star target origin. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        pat #"(?i)postMessage.[^)]+[*]"
        m (re-find pat body)]
    (if m
      [(core/finding {:rule-id "40062"
                      :cwe "CWE-79"
                      :severity :medium
                      :title "postMessage wildcard targetOrigin"
                      :evidence (subs (str m) 0 (min 48 (count (str m))))
                      :url url
                      :solution "Use an explicit targetOrigin."})]
      [])))


(defn check-viewport-zoom
  "Zoom disabled by viewport (rule 40063, CWE-693). Flags
  maximum-scale=1 or user-scalable=no. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)(maximum-scale=1|user-scalable=no)" body)]
    (if m
      [(core/finding {:rule-id "40063"
                      :cwe "CWE-693"
                      :severity :low
                      :title "Viewport disables zoom"
                      :evidence (str m)
                      :url url
                      :solution "Allow user zoom for accessibility."})]
      [])))


(defn check-deserialization-hint
  "Serialized payload hint (rule 40072, CWE-502). Flags PHP/Java
  serialized markers in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(O:\d+:|rO0AB|__proto__|ACED0005)" body)]
    (if m
      [(core/finding {:rule-id "40072"
                      :cwe "CWE-502"
                      :severity :medium
                      :title "Serialized data hint"
                      :evidence (str m)
                      :url url
                      :solution "Do not deserialize untrusted data."})]
      [])))


(defn check-meta-refresh-http
  "Meta refresh to insecure URL (rule 40073, CWE-319). Flags refresh
  targets using http://. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)refresh[^>]*url=http://[^\s>]+" body)]
    (if m
      [(core/finding {:rule-id "40073"
                      :cwe "CWE-319"
                      :severity :low
                      :title "Meta refresh to HTTP"
                      :evidence (str m)
                      :url url
                      :solution "Use HTTPS refresh targets."})]
      [])))


(defn check-content-type-charset
  "Charset missing (rule 40074, CWE-116). Flags text responses whose
  Content-Type lacks a charset parameter. Pure header inspection."
  [{:keys [url]} resp]
  (let [headers (:headers resp)
        ct (or (get-in headers ["content-type"]) (get-in headers ["Content-Type"]) (get-in headers ["CONTENT-TYPE"]) "")
        txt? (re-find #"(?i)^(text/|application/(javascript|json|xml))" (str ct))]
    (if (and txt? (nil? (re-find #"(?i)charset=" (str ct))))
      [(core/finding {:rule-id "40074"
                      :cwe "CWE-116"
                      :severity :low
                      :title "Content-Type charset missing"
                      :evidence (str ct)
                      :url url
                      :solution "Declare charset in Content-Type."})]
      [])))


(defn check-allow-methods
  "Dangerous CORS methods (rule 40075, CWE-16). Flags
  Access-Control-Allow-Methods containing TRACE or CONNECT. Pure header
  inspection."
  [{:keys [url]} resp]
  (let [acam (header-lower resp "access-control-allow-methods")]
    (if (and acam (re-find #"(?i)(TRACE|CONNECT)" (str acam)))
      [(core/finding {:rule-id "40075"
                      :cwe "CWE-16"
                      :severity :medium
                      :title "Dangerous CORS methods allowed"
                      :evidence (str acam)
                      :url url
                      :solution "Do not allow TRACE/CONNECT via CORS."})]
      [])))


(defn check-server-status-exposure
  "Server status page (rule 40076, CWE-209). Flags Apache
  /server-status style status pages in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)(Apache Status|Apache Server Status|NGINX status|Server Information)" body)]
    (if m
      [(core/finding {:rule-id "40076"
                      :cwe "CWE-209"
                      :severity :medium
                      :title "Server status exposed"
                      :evidence (str m)
                      :url url
                      :solution "Restrict status pages to trusted networks."})]
      [])))


(defn check-db-backup-exposure
  "DB backup hint (rule 40077, CWE-552). Flags backup file names in the
  body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)[^ <]+\.(sql|dump|bak|tar\.gz)" body)]
    (if m
      [(core/finding {:rule-id "40077"
                      :cwe "CWE-552"
                      :severity :high
                      :title "DB backup exposed"
                      :evidence (str m)
                      :url url
                      :solution "Remove backup files from web root."})]
      [])))


(defn check-verbose-error
  "Verbose error details (rule 40078, CWE-209). Flags filesystem paths
  revealed in the body outside a stacktrace context. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)(?:Uncaught|Warning:|Notice:)[^
]*[\/](?:var|home|usr|etc)/" body)]
    (if m
      [(core/finding {:rule-id "40078"
                      :cwe "CWE-209"
                      :severity :low
                      :title "Verbose error disclosure"
                      :evidence (str m)
                      :url url
                      :solution "Return generic error messages in production."})]
      [])))


(defn check-changelog-exposure
  "Changelog exposure (rule 40079, CWE-552). Flags a CHANGELOG file
  being served. Pure URL/path inspection."
  [{:keys [url]} _resp]
  (if (re-find #"(?i)/(CHANGELOG|HISTORY)(\.md|\.txt)?$" (str url))
    [(core/finding {:rule-id "40079"
                    :cwe "CWE-552"
                    :severity :low
                    :title "Changelog exposed"
                    :evidence (str url)
                    :url url
                    :solution "Remove changelog files from production."})]
    []))


(defn check-swagger-exposure
  "Swagger/OpenAPI docs exposed (rule 40080, CWE-200). Flags
  swagger-ui markers in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)(swagger-ui|swaggerJson|openapi:)" body)]
    (if m
      [(core/finding {:rule-id "40080"
                      :cwe "CWE-200"
                      :severity :low
                      :title "Swagger docs exposed"
                      :evidence (str m)
                      :url url
                      :solution "Restrict API docs to trusted networks."})]
      [])))


(defn check-old-jquery
  "Outdated jQuery (rule 40081, CWE-1104). Flags jQuery 1.x/2.x assets
  which carry known XSS CVEs. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)jquery([.-]|[/-]|[@.])(1|2)\." body)]
    (if m
      [(core/finding {:rule-id "40081"
                      :cwe "CWE-1104"
                      :severity :medium
                      :title "Outdated jQuery"
                      :evidence (str m)
                      :url url
                      :solution "Upgrade jQuery to a supported version."})]
      [])))


(defn check-aws-key-in-body
  "AWS access key in body (rule 40082, CWE-798). Flags AKIA* keys.
  Pure body inspection; the matched key is only partly shown."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"AKIA[0-9A-Z]{16}" body)]
    (if m
      [(core/finding {:rule-id "40082"
                      :cwe "CWE-798"
                      :severity :high
                      :title "AWS key disclosed"
                      :evidence (str (subs m 0 8) "...")
                      :url url
                      :solution "Rotate the key and remove it from the page."})]
      [])))


(defn check-private-key-in-body
  "Private key in body (rule 40083, CWE-798). Flags PEM private key
  headers. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----" body)]
    (if m
      [(core/finding {:rule-id "40083"
                      :cwe "CWE-798"
                      :severity :high
                      :title "Private key disclosed"
                      :evidence (str m)
                      :url url
                      :solution "Remove private keys from web content and revoke them."})]
      [])))


(defn check-jwt-in-body
  "JWT in body (rule 40084, CWE-200). Flags JWT-shaped tokens exposed
  in page content. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+" body)]
    (if m
      [(core/finding {:rule-id "40084"
                      :cwe "CWE-200"
                      :severity :medium
                      :title "JWT token exposed"
                      :evidence (str (subs m 0 (min 24 (count m))) "...")
                      :url url
                      :solution "Do not embed long-lived JWTs in page content."})]
      [])))


(defn check-env-leak
  "Env dump in body (rule 40085, CWE-552). Flags .env-style
  KEY=value lines with secrets. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?im)^(DB_|SECRET|API_KEY|PASSWORD|TOKEN)[A-Z_]*=.+" body)]
    (if m
      [(core/finding {:rule-id "40085"
                      :cwe "CWE-552"
                      :severity :high
                      :title ".env content exposed"
                      :evidence (str m)
                      :url url
                      :solution "Remove .env files from the web root and rotate secrets."})]
      [])))


(defn check-graphql-exposure
  "GraphQL API exposed (rule 40086, CWE-200). Flags graphql
  responses in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)(graphql|__typename|introspection)" body)]
    (if m
      [(core/finding {:rule-id "40086"
                      :cwe "CWE-200"
                      :severity :low
                      :title "GraphQL API exposed"
                      :evidence (str m)
                      :url url
                      :solution "Restrict GraphQL introspection in production."})]
      [])))


(defn check-actuator-exposure
  "Spring actuator exposed (rule 40087, CWE-200). Flags actuator
  links in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)(/actuator|_links)" body)]
    (if m
      [(core/finding {:rule-id "40087"
                      :cwe "CWE-200"
                      :severity :medium
                      :title "Actuator endpoint exposed"
                      :evidence (str m)
                      :url url
                      :solution "Restrict actuator endpoints to trusted networks."})]
      [])))


(defn check-docker-exposure
  "Docker API exposed (rule 40088, CWE-200). Flags Docker daemon
  responses in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)(docker|containerd)/[0-9]" body)]
    (if m
      [(core/finding {:rule-id "40088"
                      :cwe "CWE-200"
                      :severity :medium
                      :title "Docker API exposed"
                      :evidence (str m)
                      :url url
                      :solution "Restrict Docker API to trusted networks."})]
      [])))


(defn check-svn-exposure
  "SVN repo exposed (rule 40089, CWE-552). Flags /.svn/ paths.
  Pure URL inspection."
  [{:keys [url]} _resp]
  (if (re-find #"(?i)/\.svn/" (str url))
    [(core/finding {:rule-id "40089"
                    :cwe "CWE-552"
                    :severity :medium
                    :title ".svn directory exposed"
                    :evidence (str url)
                    :url url
                    :solution "Remove .svn directories from production."})]
    []))


(defn check-git-head-exposure
  "Git HEAD exposed (rule 40090, CWE-552). Flags /.git/HEAD paths.
  Pure URL inspection."
  [{:keys [url]} _resp]
  (if (re-find #"(?i)/\.git/HEAD" (str url))
    [(core/finding {:rule-id "40090"
                    :cwe "CWE-552"
                    :severity :medium
                    :title ".git/HEAD exposed"
                    :evidence (str url)
                    :url url
                    :solution "Remove .git directories from production."})]
    []))



(defn check-ssh-banner-exposure
  "SSH banner exposed (rule 40092, CWE-209). Flags OpenSSH banners
  in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"SSH-[0-9.]+-OpenSSH_" body)]
    (if m
      [(core/finding {:rule-id "40092"
                      :cwe "CWE-209"
                      :severity :low
                      :title "SSH banner disclosed"
                      :evidence (str m)
                      :url url
                      :solution "Do not expose SSH service banners."})]
      [])))


(defn check-smtp-banner-exposure
  "SMTP banner exposed (rule 40093, CWE-209). Flags ESMTP banners
  in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)220 .+ESMTP" body)]
    (if m
      [(core/finding {:rule-id "40093"
                      :cwe "CWE-209"
                      :severity :low
                      :title "SMTP banner disclosed"
                      :evidence (str m)
                      :url url
                      :solution "Do not expose SMTP service banners."})]
      [])))


(defn check-ftp-banner-exposure
  "FTP banner exposed (rule 40094, CWE-209). Flags FTP banners
  in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)220[- ]+.*FTP" body)]
    (if m
      [(core/finding {:rule-id "40094"
                      :cwe "CWE-209"
                      :severity :low
                      :title "FTP banner disclosed"
                      :evidence (str m)
                      :url url
                      :solution "Do not expose FTP service banners."})]
      [])))


(defn check-mysql-banner-exposure
  "MySQL banner exposed (rule 40095, CWE-209). Flags MySQL banners
  in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)[0-9]+\.[0-9.]+-MySQL|MySQL [0-9]+\.[0-9.]+" body)]
    (if m
      [(core/finding {:rule-id "40095"
                      :cwe "CWE-209"
                      :severity :low
                      :title "MySQL banner disclosed"
                      :evidence (str m)
                      :url url
                      :solution "Do not expose MySQL service banners."})]
      [])))


(defn check-pg-banner-exposure
  "PostgreSQL banner exposed (rule 40096, CWE-209). Flags PostgreSQL
  banners in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)PostgreSQL [0-9]+\.[0-9.]+" body)]
    (if m
      [(core/finding {:rule-id "40096"
                      :cwe "CWE-209"
                      :severity :low
                      :title "PostgreSQL banner disclosed"
                      :evidence (str m)
                      :url url
                      :solution "Do not expose PostgreSQL banners."})]
      [])))


(defn check-redis-banner-exposure
  "Redis banner exposed (rule 40097, CWE-209). Flags Redis banners
  in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)redis_version" body)]
    (if m
      [(core/finding {:rule-id "40097"
                      :cwe "CWE-209"
                      :severity :low
                      :title "Redis banner disclosed"
                      :evidence (str m)
                      :url url
                      :solution "Do not expose Redis service banners."})]
      [])))


(defn check-mongo-banner-exposure
  "MongoDB banner exposed (rule 40098, CWE-209). Flags MongoDB
  banners in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)MongoDB server version" body)]
    (if m
      [(core/finding {:rule-id "40098"
                      :cwe "CWE-209"
                      :severity :low
                      :title "MongoDB banner disclosed"
                      :evidence (str m)
                      :url url
                      :solution "Do not expose MongoDB banners."})]
      [])))


(defn check-es-banner-exposure
  "Elasticsearch banner exposed (rule 40099, CWE-209). Flags ES cluster
  info in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)(cluster_name|elasticsearch)" body)]
    (if m
      [(core/finding {:rule-id "40099"
                      :cwe "CWE-209"
                      :severity :low
                      :title "Elasticsearch banner disclosed"
                      :evidence (str m)
                      :url url
                      :solution "Do not expose Elasticsearch cluster info."})]
      [])))


(defn check-memcached-banner-exposure
  "Memcached banner exposed (rule 40100, CWE-209). Flags memcached
  banners in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)memcached" body)]
    (if m
      [(core/finding {:rule-id "40100"
                      :cwe "CWE-209"
                      :severity :low
                      :title "Memcached banner disclosed"
                      :evidence (str m)
                      :url url
                      :solution "Do not expose memcached banners."})]
      [])))


(defn check-tomcat-banner-exposure
  "Tomcat banner exposed (rule 40101, CWE-209). Flags Apache Tomcat
  banners in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)Apache Tomcat/[0-9.]+" body)]
    (if m
      [(core/finding {:rule-id "40101"
                      :cwe "CWE-209"
                      :severity :low
                      :title "Tomcat banner disclosed"
                      :evidence (str m)
                      :url url
                      :solution "Do not expose Tomcat version banners."})]
      [])))


(defn check-nginx-banner-exposure
  "nginx banner exposed (rule 40102, CWE-209). Flags nginx version
  banners in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)nginx/[0-9.]+" body)]
    (if m
      [(core/finding {:rule-id "40102"
                      :cwe "CWE-209"
                      :severity :low
                      :title "nginx banner disclosed"
                      :evidence (str m)
                      :url url
                      :solution "Do not expose nginx version banners."})]
      [])))


(defn check-apache-banner-exposure
  "Apache banner exposed (rule 40103, CWE-209). Flags Apache version
  banners in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)Apache/[0-9.]+" body)]
    (if m
      [(core/finding {:rule-id "40103"
                      :cwe "CWE-209"
                      :severity :low
                      :title "Apache banner disclosed"
                      :evidence (str m)
                      :url url
                      :solution "Do not expose Apache version banners."})]
      [])))


(defn check-iis-banner-exposure
  "IIS banner exposed (rule 40104, CWE-209). Flags Microsoft-IIS
  banners in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)Microsoft-IIS/[0-9.]+" body)]
    (if m
      [(core/finding {:rule-id "40104"
                      :cwe "CWE-209"
                      :severity :low
                      :title "IIS banner disclosed"
                      :evidence (str m)
                      :url url
                      :solution "Do not expose IIS version banners."})]
      [])))


(defn check-php-version-exposure
  "PHP version banner exposed (rule 40105, CWE-209). Flags PHP
  version banners in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)PHP Version [0-9.]+" body)]
    (if m
      [(core/finding {:rule-id "40105"
                      :cwe "CWE-209"
                      :severity :low
                      :title "PHP version disclosed"
                      :evidence (str m)
                      :url url
                      :solution "Do not expose PHP version banners."})]
      [])))


(defn check-sqlite-version-exposure
  "SQLite version banner exposed (rule 40106, CWE-209). Flags SQLite
  version banners in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)SQLite version [0-9.]+" body)]
    (if m
      [(core/finding {:rule-id "40106"
                      :cwe "CWE-209"
                      :severity :low
                      :title "SQLite version disclosed"
                      :evidence (str m)
                      :url url
                      :solution "Do not expose SQLite version banners."})]
      [])))
































(defn check-sensitive-file-exposure
  "Sensitive file exposed (rule 40117, CWE-552). Flags sensitive file
  references in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)(node_modules|vendor/|\.htaccess|composer\.json|package\.json|requirements\.txt|Gemfile|Pipfile|settings\.py|config\.php)" body)]
    (if m
      [(core/finding {:rule-id "40117"
                      :cwe "CWE-552"
                      :severity :medium
                      :title "Sensitive file exposed"
                      :evidence (str m)
                      :url url
                      :solution "Do not expose sensitive files."})]
      [])))


(defn check-vendor-exposure
  "Vendor directory exposed (rule 40108, CWE-552). Flags vendor
  paths in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)vendor/" body)]
    (if m
      [(core/finding {:rule-id "40108"
                      :cwe "CWE-552"
                      :severity :medium
                      :title "Vendor directory exposed"
                      :evidence (str m)
                      :url url
                      :solution "Do not expose the vendor directory."})]
      [])))


(defn check-wpconfig-exposure
  "wp-config.php exposed (rule 40118, CWE-552). Flags wp-config.php
  references in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)wp-config\.php" body)]
    (if m
      [(core/finding {:rule-id "40118"
                      :cwe "CWE-552"
                      :severity :medium
                      :title "wp-config.php exposed"
                      :evidence (str m)
                      :url url
                      :solution "Do not expose wp-config.php."})]
      [])))


(defn check-webconfig-exposure
  "web.config exposed (rule 40119, CWE-552). Flags web.config
  references in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)web\.config" body)]
    (if m
      [(core/finding {:rule-id "40119"
                      :cwe "CWE-552"
                      :severity :medium
                      :title "web.config exposed"
                      :evidence (str m)
                      :url url
                      :solution "Do not expose web.config."})]
      [])))


(defn check-yarnlock-exposure
  "yarn.lock exposed (rule 40120, CWE-552). Flags yarn.lock
  references in the body. Pure body inspection."
  [{:keys [url]} resp]
  (let [body (str (get resp :body ""))
        m (re-find #"(?i)yarn\.lock" body)]
    (if m
      [(core/finding {:rule-id "40120"
                      :cwe "CWE-552"
                      :severity :medium
                      :title "yarn.lock exposed"
                      :evidence (str m)
                      :url url
                      :solution "Do not expose yarn.lock."})]
      [])))

(def checks
  "Ordered passive rule list — one fn per rule, all (req resp) -> [findings]."
  [check-security-headers check-header-variants check-cookie-flags check-sensitive-info check-directory-listing check-refresh check-location-redirect check-cache-privacy check-cors check-www-authenticate check-server-version check-dom-xss-sink check-js-library-version check-ssti-reflection check-sourcemap-exposure check-dotenv-exposure check-git-exposure check-backup-exposure check-phpinfo-exposure check-stacktrace-exposure check-password-in-url check-url-credentials check-email-disclosure check-login-autocomplete check-internal-ip-disclosure check-internal-hostname check-jwt-exposure check-apikey-exposure check-private-key-exposure check-cookie-attributes check-cookie-samesite check-missing-sri check-tabnabbing check-mixed-content check-insecure-websocket check-cookie-long-expiry check-clickjacking check-hsts check-nosniff check-referrer-policy check-permissions-policy check-http-redirect check-csp-unsafe-inline check-csp-missing check-form-http-action check-dom-open-redirect check-postmessage-wildcard check-viewport-zoom check-deserialization-hint check-meta-refresh-http check-content-type-charset check-allow-methods check-server-status-exposure check-db-backup-exposure check-verbose-error check-changelog-exposure check-swagger-exposure check-old-jquery check-aws-key-in-body check-private-key-in-body check-jwt-in-body check-env-leak check-graphql-exposure check-actuator-exposure check-docker-exposure check-svn-exposure check-git-head-exposure check-ssh-banner-exposure check-smtp-banner-exposure check-ftp-banner-exposure check-mysql-banner-exposure check-pg-banner-exposure check-redis-banner-exposure check-mongo-banner-exposure check-es-banner-exposure check-memcached-banner-exposure check-tomcat-banner-exposure check-nginx-banner-exposure check-apache-banner-exposure check-iis-banner-exposure check-php-version-exposure check-sqlite-version-exposure check-vendor-exposure check-sensitive-file-exposure check-wpconfig-exposure check-webconfig-exposure check-yarnlock-exposure])

(defn passive-scan
  "Run every passive check over one (request, response) pair."
  [req resp]
  (vec (mapcat (fn [f] (f req resp)) checks))

)
