'''
    #Get icmp packets with destination AS 224 in the oslo-gw:
	rwfilter --start-date=2011/01/03:00 --end-date=2011/01/10:00 --proto=1,58 --pass-destination=/home/linneafg/silk-data/RawDataFromFilter/icmp-in.rw --data-rootdir=/home/linneafg/silk-data/oslo-gw
	
    #Sorts them by start time
	rwsort --fields=stime --output-path=/home/linneafg/silk-data/RawDataFromFilter/icmp-in-sorted.rw /home/linneafg/silk-data/RawDataFromFilter/icmp-in.rw

'''

# Import the PySiLK bindings
from silk import *
from NumberOfPackets import *
from datetime import datetime,timedelta
import numpy as np


def icmpDetection(silkFile):
    f = open("ThresholdNetFlow/Detections/ICMP.txt", "a")

    startTime = datetime.strptime("2011-01-03 00:00:00", '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime("2011-01-10 00:00:00", '%Y-%m-%d %H:%M:%S')
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)
    records = []

    numberOfIcmpPackets = []

    i = 0
    f.write("Time, Change, Value, Mean of the last 10 minutes")
    for rec in infile:
        if rec.stime >= stopTime:
            break
        if rec.stime <= startTime:
            continue
        if rec.stime >= startTime + timedelta(minutes = 1):
            packets = numberOfPackets(records)
            
            numberOfIcmpPackets.append(packets)

            if i >=10:
                if abs(numberOfIcmpPackets[i] - np.nanmean(numberOfIcmpPackets[i-10: i-1])) > 100:
                    f.write("\n" + str(startTime) + "," + str(abs(numberOfIcmpPackets[i] - np.nanmean(numberOfIcmpPackets[i-10: i-1]))) + "," + str(numberOfIcmpPackets[i]) + "," + str(np.nanmean(numberOfIcmpPackets[i-10: i-1])))
    
            records = []
            startTime = startTime + timedelta(minutes = 1)
            i+= 1
        records.append(rec)
    
    f.close()
    infile.close()

    
icmpDetection("/home/linneafg/silk-data/RawDataFromFilter/icmp-in-sorted.rw")