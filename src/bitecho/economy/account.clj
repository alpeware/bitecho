(ns bitecho.economy.account)

(defrecord AccountState [balance seq deps])

(defrecord Transfer [sender receiver amount seq deps signature])
