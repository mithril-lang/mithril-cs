(ns mithril.web-scanner.review-regression-test
  (:require [clojure.test :refer [deftest is]]
            [mithril.web-scanner.passive :as p]))
(def target {:url "https://example.test/"})
(deftest private-ip-literals-test
  (doseq [body ["10.0.0.1" "192.168.255.255:443" "172.16.0.5" "172.31.0.1" "127.0.0.1"]]
    (is (= 1 (count (p/check-internal-ip-disclosure target {:body body})))))
  (doseq [body ["10 20 30 40" "10.256.0.1" "192.168.1.999" "x10.0.0.1" "110.0.0.1" "10.0.0.1.example" "172.32.0.1" "8.8.8.8"]]
    (is (empty? (p/check-internal-ip-disclosure target {:body body})))))
(deftest namespace-and-http-context-test
  (doseq [body ["<svg xmlns='http://www.w3.org/2000/svg'/>" "<svg xmlns:xlink=\"http://www.w3.org/1999/xlink\"/>"]]
    (is (empty? (p/check-mixed-content target {:body body})))))
(deftest fetch-reference-preserved-test
  (doseq [body ["<img src='http://example.test/a.png'>" "<svg><use href='http://example.test/i.svg#x'/></svg>" "a{background:url(http://example.test/a.png)}"]]
    (is (= :medium (:severity (first (p/check-mixed-content target {:body body})))))))
(deftest unresolved-reference-retained-test
  (doseq [body ["<a href='http://example.test'>link</a>" "fetch('http://example.test/api')"]]
    (let [f (first (p/check-mixed-content target {:body body}))]
      (is (= "40049" (:rule-id f)))
      (is (= :info (:severity f))))))
