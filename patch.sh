sed -i 's/(ns bitecho.simulator.contagion-pure-e2e/(ns bitecho.simulator.account-e2e/' dev/bitecho/simulator/account_e2e.clj
sed -i '/\[bitecho.crypto :as crypto\]/a \            [bitecho.economy.account :as account]' dev/bitecho/simulator/account_e2e.clj
