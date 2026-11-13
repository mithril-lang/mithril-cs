(ns mithril.cs.cljs-build
  (:require [cljs.build.api :as build] [clojure.java.shell :as shell]))
(defn -main [& _]
  (build/build (build/inputs "src" "test")
               {:main 'mithril.cs.cljs-runner :target :nodejs :optimizations :none
                :output-to "out/tests.js" :output-dir "out/cljs" :parallel-build false})
  (let [{:keys [exit out err]} (shell/sh "node" "out/tests.js")]
    (print out) (binding [*out* *err*] (print err))
    (shutdown-agents)
    (when-not (zero? exit) (System/exit exit))))
