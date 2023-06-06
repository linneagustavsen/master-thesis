from datetime import timedelta
from NetFlow.Entropy.findBestRocScore import findBestRocScore


pathToRawFiles="/data/master-dump/fresh-netflow-data/master-dump/"
systemId = "hoytek-gw2"
baseFile="2023-03-24_14-18-sorted.rw"  
silkFile = pathToRawFiles+systemId + "/"+ baseFile
start = "2023-03-24 14:00:00"
stop = "2023-03-24 18:00:00"
attackDate = "24.03.23"

frequencies = [timedelta(seconds=5),timedelta(seconds=10), timedelta(seconds=20), timedelta(seconds=30), timedelta(seconds=40), timedelta(seconds=50),timedelta(minutes=1)]
for frequency in frequencies:
    for i in range(1,21):
        interval = timedelta(minutes=i)
        for k in range(1,21):
            findBestRocScore(silkFile, start, stop, systemId, frequency, interval, k, attackDate)