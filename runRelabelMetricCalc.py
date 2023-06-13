from datetime import timedelta
from NetFlow.Entropy.RelabelMetricCalc import relabelMetricCalc



systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]

intervals = [timedelta(minutes = 5), timedelta(minutes = 10), timedelta(minutes = 15)]
attackDate = "08.03.23"
for systemId in systems:
    print(systemId)
    relabelMetricCalc(systemId, intervals, attackDate)

'''attackDate = "24.03.23"
for systemId in systems:
    print(systemId)
    relabelMetricCalc(systemId, intervals, attackDate)'''