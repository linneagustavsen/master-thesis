from datetime import timedelta
from pathlib import Path
from NetFlow.TopKFlows.topkflow import topkflows, topkflows2 
from HelperFunctions.GeneralizedEntropy import generalizedEntropy
start="2011-01-19 06:56:00"
stop="2011-01-19 08:37:00"
interval = timedelta(minutes = 1)
silkFile = "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/dip-in-destination-ips-sorted.rw"
#topkflows2(silkFile, start, stop, interval, 20, "19.01", "oslo-gw")

p = Path('NetwFlow')
q = p / 'RandomForest' / 'RawData'
path = "training"
f =open(str(q) +"/"+ path+"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(0.1)+ "."+str(1)+ ".pkl")