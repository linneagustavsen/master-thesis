from datetime import timedelta
from NetFlow.TopKFlows.topkflow import topkflows, topkflows2 
start="2011-01-19 06:56:00"
stop="2011-01-19 08:37:00"
interval = timedelta(minutes = 1)
silkFile = "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/dip-in-destination-ips-sorted.rw"
topkflows2(silkFile, start, stop, interval, 20, "19.01", "oslo-gw")
