'''
	#Get icmp packets with type "destination unreachable"
	rwfilter --start-date=2011/01/03:00 --end-date=2011/01/10:00 --proto=1,58 --icmp-type=3 --pass-destination=/home/linneafg/silk-data/RawDataFromFilter/icmp3-in.rw --data-rootdir=/home/linneafg/silk-data/oslo-gw

    #Sorts them by start time
    rwsort --fields=stime --output-path=/home/linneafg/silk-data/RawDataFromFilter/icmp3-in-sorted.rw /home/linneafg/silk-data/RawDataFromFilter/icmp3-in.rw

'''

# Import the PySiLK bindings
from silk import *
from NumberOfPackets import *
from datetime import datetime,timedelta
from MakePlot import *


def icmpDetection(silkFile):

    startTime = datetime.strptime("2011-01-03 00:00:00", '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime("2011-01-10 00:00:00", '%Y-%m-%d %H:%M:%S')
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)
    records = []

    numberOfIcmpDstUnreachablePackets = []

    timeArray = []

    for rec in infile:
        if rec.stime >= stopTime:
            break
        if rec.stime <= startTime:
            continue
        if rec.stime >= startTime + timedelta(minutes = 1):
            
            numberOfIcmpDstUnreachablePackets.append(numberOfPackets(records))
            
            timeArray.append(rec.stime)

            records = []
            startTime = startTime + timedelta(minutes = 1)
        records.append(rec)
        

    infile.close()

    makePlot(numberOfIcmpDstUnreachablePackets, timeArray, "Number of ICMP Destination unreachable packets 1 week")

icmpDetection("/home/linneafg/silk-data/RawDataFromFilter/icmp3-in-sorted.rw")