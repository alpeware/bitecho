(ns bitecho.api-test
  (:require [bitecho.api :as api]
            [clojure.core.async :as async]
            [clojure.test :refer [deftest is]]))

(deftest test-send-direct-message
  (let [node {:events-in (async/chan 10)}
        dest "dest-pub"
        payload (.getBytes "secret")
        ticket {:payload-hash "hash" :nonce 1 :public-key "pub" :signature "sig"}]
    (api/send-direct-message node dest payload ticket 10 100 (java.util.Random. 42))
    (let [[event _] (async/alts!! [(:events-in node) (async/timeout 100)])]
      (is (some? event))
      (is (= :route-directed-message (:type event)))
      (is (= dest (:destination (:envelope event)))))))
