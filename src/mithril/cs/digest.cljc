(ns mithril.cs.digest
  #?(:cljs (:require [goog.crypt :as crypt] [goog.crypt.Sha256]))
  #?(:clj (:import [java.security MessageDigest] [java.nio.charset StandardCharsets])))

(defn sha256 [text]
  #?(:clj (format "%064x" (java.math.BigInteger. 1
                           (.digest (MessageDigest/getInstance "SHA-256")
                                    (.getBytes ^String text StandardCharsets/UTF_8))))
     :cljs (let [hash (goog.crypt.Sha256.)]
             (.update hash (crypt/stringToUtf8ByteArray text))
             (crypt/byteArrayToHex (.digest hash)))))
