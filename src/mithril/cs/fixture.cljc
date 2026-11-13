(ns mithril.cs.fixture
  "Controlled in-process target. No sockets, real credentials or user code."
  (:require [mithril.cs.digest :as digest]
            #?(:clj [clojure.edn :as edn] :cljs [cljs.reader :as edn])))

(def vulnerable-source "{:tenant-isolation false}")
(def repaired-source "{:tenant-isolation true}")

(defn sandbox [target revision source]
  (when-not (and (string? source) (<= (count source) 128)
                (contains? #{vulnerable-source repaired-source} source)
                (string? target) (string? revision)
                (re-matches #"[0-9a-f]{40}" revision))
    (throw (ex-info "Invalid fixture manifest" {:code :invalid-fixture})))
  {:target target :revision revision :source source
   :source-sha256 (digest/sha256 source)
   :tenant-isolation (:tenant-isolation (edn/read-string source))})

(defn request [sandbox {:keys [actor object]}]
  (cond
    (not (contains? #{:alice :bob} actor)) {:status 401}
    (not= "doc-a" object) {:status 404}
    (and (:tenant-isolation sandbox) (not= actor :alice)) {:status 403}
    :else {:status 200 :object "doc-a" :owner :alice :value "synthetic-only"}))
