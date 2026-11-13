(ns mithril.cs.cljs-runner
  (:require [cljs.test :as test]
            [mithril.cs.core-test]
            [mithril.cs.pentest-test]))
(defmethod test/report [::test/default :end-run-tests] [result]
  (when-not (test/successful? result) (set! (.-exitCode js/process) 1)))
(defn -main [& _] (test/run-tests 'mithril.cs.core-test 'mithril.cs.pentest-test))
(set! *main-cli-fn* -main)
