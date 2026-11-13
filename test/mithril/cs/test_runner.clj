(ns mithril.cs.test-runner
  (:require [clojure.test :as test]
            [mithril.cs.core-test]
            [mithril.cs.source-test]
            [mithril.cs.pentest-test]))
(defn run [& _]
  (let [{:keys [fail error]} (test/run-tests 'mithril.cs.core-test 'mithril.cs.source-test 'mithril.cs.pentest-test)]
    (when (pos? (+ fail error)) (System/exit 1))))
(defn -main [& args] (apply run args))
