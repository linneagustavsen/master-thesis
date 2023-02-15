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
import numpy as np


def icmpDetection(silkFile):
    f = open("ThresholdNetFlow/Detections/ICMPDstUnreachable.txt", "a")

    startTime = datetime.strptime("2011-01-03 00:00:00", '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime("2011-01-10 00:00:00", '%Y-%m-%d %H:%M:%S')
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)
    records = []

    numberOfIcmpDstUnreachablePackets = []

    i =0
    f.write("Time, Change, Value, Mean of the last 10 minutes")
    for rec in infile:
        if rec.stime >= stopTime:
            break
        if rec.stime <= startTime:
            continue
        if rec.stime >= startTime + timedelta(minutes = 1):
            
            numberOfIcmpDstUnreachablePackets.append(numberOfPackets(records))
            
            if i >=10:
                if abs(numberOfIcmpDstUnreachablePackets[i] - np.nanmean(numberOfIcmpDstUnreachablePackets[i-10: i-1])) > 50:
                    f.write("\n" + str(startTime) + "," + str(abs(numberOfIcmpDstUnreachablePackets[i] - np.nanmean(numberOfIcmpDstUnreachablePackets[i-10: i-1]))) + "," + str(numberOfIcmpDstUnreachablePackets[i]) + "," + str(np.nanmean(numberOfIcmpDstUnreachablePackets[i-10: i-1])))

            records = []
            startTime = startTime + timedelta(minutes = 1)
            i += 1
        records.append(rec)
        

    infile.close()
    f.close()


icmpDetection("/home/linneafg/silk-data/RawDataFromFilter/icmp3-in-sorted.rw")