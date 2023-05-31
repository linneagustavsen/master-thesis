from datetime import timedelta
from NetFlow.Entropy.RelabelMetricCalc import relabelMetricCalc


systems = ["tromso-gw5",  "teknobyen-gw1","hoytek-gw2", "bergen-gw3", "trd-gw", "ifi2-gw5"]

intervals = [timedelta(minutes = 5), timedelta(minutes = 10), timedelta(minutes = 15)]
attackDate = "17.03.23"
for systemId in systems:
    print(systemId)
    relabelMetricCalc(systemId, intervals, attackDate)

'''attackDate = "24.03.23"
for systemId in systems:
    print(systemId)
    relabelMetricCalc(systemId, intervals, attackDate)'''