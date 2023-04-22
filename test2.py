'''from datetime import timedelta
from NetFlow.TopKFlows.topkflow import topkflows, topkflows2 
from HelperFunctions.GeneralizedEntropy import generalizedEntropy
start="2011-01-19 06:56:00"
stop="2011-01-19 08:37:00"
interval = timedelta(minutes = 1)
silkFile = "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/dip-in-destination-ips-sorted.rw"
topkflows2(silkFile, start, stop, interval, 20, "19.01", "oslo-gw")
'''
'''import math
def generalizedEntropy(alpha, Pi):
    sumProb = 0
    for pi in Pi:
        sumProb += pi**alpha

    return 1/(1-alpha)*math.log(sumProb, 2)

def generalizedEntropy2(alpha, Pi):
    sumProb = 0
    for pi in Pi:
        sumProb += pi**alpha

    fraction = 1/(1-alpha)

    return fraction*math.log(sumProb, 2)
Pi = [0.1, 0.3, 0.1, 0.2, 0.3]
print(generalizedEntropy(10, Pi))
print(generalizedEntropy2(10, Pi))'''


from datetime import timedelta
from NetFlow.Threshold.SYNDetection import synDetection

from Telemetry.Entropy.Detection import detectionEntropyTelemetry

baseFile="two-hours-2011-02-08_10-12-sorted.rw"         
systems = ["oslo-gw"]
start = "2011-02-08 10:00:00"
stop = "2011-02-08 12:00:00"
startCombined = "2011-02-08 10:00:00"
stopCombined = "2011-02-08 12:00:00"
frequency = timedelta(minutes = 1)
interval = timedelta(minutes = 10)
pathToRawFiles="/home/linneafg/silk-data/RawDataFromFilter/"
attackDate="08.02.11"
systemId =  "oslo-gw"
silkFileSyn = pathToRawFiles+systemId + "/tcp-syn-"+ baseFile
synDetection(silkFileSyn, start, stop, systemId, 10, 2, attackDate)