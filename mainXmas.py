from datetime import timedelta
from NetFlow.TopKFlows.topkflowCalculation import topkflows2

def main(start, stop, systems, attackDate):
    silkFile = pathToRawFiles+systemId + "/"+ baseFile
    for systemId in systems:
        topkflows2(silkFile, start, stop, timedelta(minutes = 1), 20, attackDate, systemId)


#Attack 1
baseFile="twelve-hours-2023-03-08_08-20-sorted.rw"         
systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
start = "2023-03-08 08:00:00"
stop = "2023-03-08 20:00:00"
pathToRawFiles="/data/master-dump/master-thesis/tmp/data/"
attackDate="08.03.23"
