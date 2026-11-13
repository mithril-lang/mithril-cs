(ns mithril.web-scanner.test-fs
  "Test-only, root-bound fixture resource reader; no production filesystem capability."
  (:refer-clojure :exclude [read]))
(defn host-filesystem [{:keys [root]}] (.toRealPath (java.nio.file.Paths/get root (make-array String 0)) (make-array java.nio.file.LinkOption 0)))
(defn read [root path]
  (let [p (.toRealPath (.resolve root path) (make-array java.nio.file.LinkOption 0))]
    (when-not (.startsWith p root) (throw (ex-info "fixture outside root" {})))
    (slurp (str p))))
