(ns mithril.cs.edge-build
  (:require [cljs.build.api :as cljs] [clojure.java.io :as io]))
(defn -main [& _]
  (cljs/build "src" {:main 'mithril.cs.edge :target :webworker :optimizations :advanced
                     :output-dir "/tmp/mithril-edge-build" :output-to "/tmp/mithril-edge-engine.js"
                     :parallel-build false})
  (spit "/tmp/mithril-edge-engine.mjs"
        (str (slurp "/tmp/mithril-edge-engine.js") "\nexport default globalThis.MITHRIL_EDGE;\n")))
