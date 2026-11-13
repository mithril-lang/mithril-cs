(ns mithril.cs.source
  "Bounded local reader. Never evaluates, imports or builds inspected source."
  (:require [clojure.string :as str]
            [mithril.cs.rules :as rules])
  (:import [java.nio ByteBuffer]
           [java.nio.charset CodingErrorAction StandardCharsets]
           [java.nio.file Files LinkOption Path Paths StandardOpenOption]
           [java.security MessageDigest]))

(def limits {:entries 10000 :files 250 :file-bytes 262144 :total-bytes 4194304 :depth 32})
(def extensions #{"clj" "cljc" "cljs" "js" "jsx" "ts" "tsx" "py" "java" "go" "rb" "rs"})
(def nofollow (into-array LinkOption [LinkOption/NOFOLLOW_LINKS]))

(defn sha256 [bytes]
  (format "%064x" (java.math.BigInteger. 1 (.digest (MessageDigest/getInstance "SHA-256") bytes))))

(defn fail! [code] (throw (ex-info (name code) {:code code})))

(defn path [s] (.normalize (.toAbsolutePath (Paths/get s (make-array String 0)))))

(defn root-path [root]
  (let [p (path root)]
    ;; Canonical comparison denies symbolic links in the root or any ancestor.
    (when-not (and (Files/isDirectory p nofollow) (= p (.toRealPath p (make-array LinkOption 0))))
      (fail! :invalid-root))
    p))

(defn source-file? [^Path p]
  (contains? extensions (last (str/split (str (.getFileName p)) #"\."))))

(defn bounded-bytes [^Path p remaining]
  (when (Files/isSymbolicLink p) (fail! :symlink-changed))
  (with-open [in (Files/newInputStream p (into-array java.nio.file.OpenOption [LinkOption/NOFOLLOW_LINKS]))]
    (let [n (min (:file-bytes limits) remaining)
          bytes (.readNBytes in (int (inc n)))]
      (when (> (alength bytes) n) (fail! :source-budget-exceeded))
      bytes)))

(defn utf8 [bytes]
  (str (.decode (doto (.newDecoder StandardCharsets/UTF_8)
                  (.onMalformedInput CodingErrorAction/REPORT)
                  (.onUnmappableCharacter CodingErrorAction/REPORT))
                (ByteBuffer/wrap bytes))))

(defn scan
  "Strict entry/file/byte/depth limits. Symlinks are excluded, never followed.
   Intended for a quiescent caller-owned local checkout, not a hostile live FS."
  [root]
  (let [base (root-path root)]
    (with-open [stream (Files/walk base (int (inc (:depth limits)))
                                  (make-array java.nio.file.FileVisitOption 0))]
      (let [entries (vec (take (inc (:entries limits)) (iterator-seq (.iterator stream))))]
        (when (> (count entries) (:entries limits)) (fail! :entry-budget-exceeded))
        (when (some #(> (.getNameCount (.relativize base ^Path %)) (:depth limits)) entries)
          (fail! :depth-budget-exceeded))
        (reduce
         (fn [report ^Path p]
           (let [relative (str (.relativize base p))]
             (cond
               (Files/isSymbolicLink p) (update report :excluded conj {:path relative :reason :symlink})
               (not (Files/isRegularFile p nofollow)) report
               (not (source-file? p)) (update report :excluded conj {:path relative :reason :unsupported-type})
               :else
               (do
                 (when (>= (count (:files report)) (:files limits)) (fail! :file-budget-exceeded))
                 (let [bytes (bounded-bytes p (- (:total-bytes limits) (:bytes report)))
                       digest (sha256 bytes)
                       matches (rules/review-text (utf8 bytes))]
                   (-> report
                       (update :bytes + (alength bytes))
                       (update :files conj {:path relative :sha256 digest :bytes (alength bytes)})
                       (update :candidates into
                               (map #(assoc % :path relative :source-sha256 digest) matches))))))))
         {:files [] :excluded [] :bytes 0 :candidates []} (sort-by str entries))))))
