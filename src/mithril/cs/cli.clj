(ns mithril.cs.cli
  (:require [mithril.cs.core :as core]
            [mithril.cs.source :as source]
            [mithril.cs.fixture :as fixture] [mithril.cs.pentest :as pentest]))

(def usage "mithril-cs review <local-root> --authorized\nmithril-cs pentest-fixture --authorized\nOutput: EDN to stdout. Read-only lexical review; no active pentest or model calls.")

(defn review [root]
  (let [now (System/currentTimeMillis)
        target (str (source/root-path root))
        grant {:id "local-owner" :tenant "local" :project "local" :target "local-source"
               :operation :source-review :authorized? true :expires-at (+ now 60000) :max-steps 1}
        run-id (str (java.util.UUID/randomUUID))
        run (core/admit-step (core/start-run grant run-id now) grant now)
        report (source/scan target)
        elapsed (- (System/currentTimeMillis) now)]
    (when (>= elapsed 60000) (source/fail! :review-expired))
    (let [result (reduce (fn [state [index evidence]]
                          (core/record-evidence state
                            (assoc evidence :id (str "candidate-" index)
                                   :run-id run-id :target "local-source")))
                        run (map-indexed vector (:candidates report)))
          coverage {:status (if (seq (:files report)) :complete :empty)
                    :method :lexical-review
                    :files (count (:files report)) :excluded (count (:excluded report))
                    :exploit-validation :not-performed}]
      (assoc (core/finish result coverage)
             :source (dissoc report :candidates)
             :elapsed-ms elapsed :models-called 0))))

(defn fixture-assessment []
  (let [now (System/currentTimeMillis)
        sandbox (fixture/sandbox "bundled-idor" (apply str (repeat 40 "0")) fixture/vulnerable-source)
        grant {:id "local-fixture-owner" :tenant "synthetic" :project "fixture" :target "bundled-idor"
               :operation :fixture-pentest :authorized? true :expires-at (+ now 60000) :max-steps 4
               :source-revision (:revision sandbox) :source-sha256 (:source-sha256 sandbox)}]
    (pentest/assess sandbox grant (str (java.util.UUID/randomUUID))
                    {:clock #(System/currentTimeMillis) :current-grant (constantly grant)})))

(defn invoke [args]
  (if (= ["pentest-fixture" "--authorized"] (vec args))
    {:exit 0 :report (fixture-assessment)}
    (if (or (empty? args) (= ["--help"] (vec args)))
    {:exit 0 :text usage}
    (if (and (= 3 (count args)) (= "review" (first args)) (= "--authorized" (last args)))
      (try
        (let [report (review (second args))]
          {:exit (if (= :completed (:status report)) 0 3) :report report})
        (catch Exception e
          {:exit 2 :report {:status :failed :code (or (:code (ex-data e)) :reader-error)}}))
      {:exit 2 :text usage}))))

(defn -main [& args]
  (let [{:keys [exit text report]} (invoke args)]
    (if text (println text) (prn report))
    (when-not (zero? exit) (System/exit exit))))
