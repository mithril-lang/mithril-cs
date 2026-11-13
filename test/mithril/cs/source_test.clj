(ns mithril.cs.source-test
  (:require [clojure.test :refer [deftest is]]
            [mithril.cs.source :as source]
            [mithril.cs.cli :as cli])
  (:import [java.nio.file Files Path]
           [java.nio.file.attribute FileAttribute]))

(defn temporary [f]
  (let [root (.toRealPath (Files/createTempDirectory "mcs-test-" (make-array FileAttribute 0))
                               (make-array java.nio.file.LinkOption 0))]
    (try (f root)
         (finally
           (with-open [paths (Files/walk root (make-array java.nio.file.FileVisitOption 0))]
             (doseq [^Path p (reverse (sort-by str (iterator-seq (.iterator paths))))]
               (Files/deleteIfExists p)))))))

(deftest actual-source-review
  (temporary
   (fn [^Path root]
     (spit (str (.resolve root "app.js")) "eval(input)\n")
     (spit (str (.resolve root "readme.md")) "not inspected")
     (let [report (source/scan (str root))
           result (cli/invoke ["review" (str root) "--authorized"])]
       (is (= 1 (count (:files report))))
       (is (= 1 (count (:candidates report))))
       (is (= 64 (count (get-in report [:files 0 :sha256]))))
       (is (= :unsupported-type (get-in report [:excluded 0 :reason])))
       (is (= 0 (:exit result)))
       (is (= :needs-review (get-in result [:report :findings 0 :status])))
       (is (= :not-performed (get-in result [:report :coverage :exploit-validation])))
       (is (= 0 (get-in result [:report :models-called])))))))

(deftest permissions-and-empty
  (is (= 2 (:exit (cli/invoke ["review" "." ]))))
  (is (= 0 (:exit (cli/invoke ["--help"]))))
  (temporary #(is (= 3 (:exit (cli/invoke ["review" (str %) "--authorized"]))))))

(deftest excludes-symlinks
  (temporary
   (fn [^Path root]
     (spit (str (.resolve root "ok.js")) "const x = 1;")
     (Files/createSymbolicLink (.resolve root "linked.js") (.resolve root "ok.js")
                              (make-array FileAttribute 0))
     (let [report (source/scan (str root))]
       (is (= 1 (count (:files report))))
       (is (= :symlink (get-in report [:excluded 0 :reason])))))))

(deftest limits-and-encoding-fail-closed
  (temporary
   (fn [^Path root]
     (spit (str (.resolve root "big.js")) (apply str (repeat 100 "x")))
     (with-redefs [source/limits (assoc source/limits :file-bytes 10)]
       (is (= :source-budget-exceeded (get-in (cli/invoke ["review" (str root) "--authorized"]) [:report :code]))))
     (with-redefs [source/limits (assoc source/limits :files 0)]
       (is (thrown? Exception (source/scan (str root)))))
     (with-redefs [source/limits (assoc source/limits :entries 1)]
       (is (thrown? Exception (source/scan (str root)))))
     (Files/write (.resolve root "invalid.py") (byte-array [(unchecked-byte 255)])
                  (make-array java.nio.file.OpenOption 0))
     (is (= 2 (:exit (cli/invoke ["review" (str root) "--authorized"])))))))

(deftest candidate-and-total-budgets
  (temporary
   (fn [^Path root]
     (spit (str (.resolve root "app.js")) "eval(x)\neval(y)")
     (with-redefs [source/limits (assoc source/limits :candidates 1)]
       (is (= :candidate-budget-exceeded (get-in (cli/invoke ["review" (str root) "--authorized"]) [:report :code]))))
     (with-redefs [source/limits (assoc source/limits :total-bytes 5)]
       (is (= :source-budget-exceeded (get-in (cli/invoke ["review" (str root) "--authorized"]) [:report :code])))))))
