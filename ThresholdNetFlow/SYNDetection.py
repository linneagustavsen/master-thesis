'''
    #Get icmp packets with destination AS 224 in the oslo-gw:
	rwfilter --start-date=2011/01/03:00 --end-date=2011/01/10:00 --proto=6,56 --flags-all=S/SA --pass-destination=/home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in.rw --data-rootdir=/home/linneafg/silk-data/oslo-gw
	
    #Sorts them by start time
	rwsort --fields=stime --output-path=/home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in-sorted.rw  /home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in.rw 

'''

# Import the PySiLK bindings
from silk import *
from datetime import datetime
import numpy as np

def synDetection(silkFile):
    f = open("ThresholdNetFlow/Detections/TCPSYN.txt", "a")
    #startTime = datetime.strptime("2010-12-26 06:00:00", '%Y-%m-%d %H:%M:%S')
    startTime = datetime.strptime("2011-01-03 00:00:00", '%Y-%m-%d %H:%M:%S')
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)
    synPacketsPerFlow = []
    i = 0

    f.write("Time, Change, Value, Mean of the last 10 minutes")
    for rec in infile:
        synPacketsPerFlow.append(rec.packets)
        
        if i >= 10:
            if rec.packets >= 5:
                f.write("\n" + str(startTime) + "," + str(abs(synPacketsPerFlow[i] - np.nanmean(synPacketsPerFlow[i-10: i-1]))) + "," + str(synPacketsPerFlow[i]) + "," + str(np.nanmean(synPacketsPerFlow[i-10: i-1])))
        i += 1
    infile.close()

synDetection("/home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in-sorted.rw")
#synDetection("/home/linneafg/silk-data/RawDataFromFilter/tcpSyn-in-sorted-time.rw")