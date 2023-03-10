'''
How to get the flows in a file format:

    #Get icmp packets with destination AS 224 in the oslo-gw:
	rwfilter --start-date=2011/01/03:00 --end-date=2011/01/10:00 --proto=1,58 --pass-destination=/home/linneafg/silk-data/RawDataFromFilter/icmp-in.rw --data-rootdir=/home/linneafg/silk-data/oslo-gw
	
    #Sorts them by start time
	rwsort --fields=stime --output-path=/home/linneafg/silk-data/RawDataFromFilter/icmp-in-sorted.rw /home/linneafg/silk-data/RawDataFromFilter/icmp-in.rw

'''

from silk import *
from NumberOfPackets import *
from datetime import datetime,timedelta
import numpy as np

'''

    Calculates the number of ICMP packets and alerts in case of an anomaly
    Input:  File with flow records sorted on time, 
            start time as a string, 
            a aggregation interval as a timedelta object, 
            a window size of how far back we should compare the values
'''

def icmpDetection(silkFile, start, interval, windowSize):
    #Open file to write alerts to
    f = open("NetFlow/Threshold/Detections/ICMP.csv", "a")
    #Write the column titles to the files
    f.write("Time, Change, Value, Mean of the last "+ str(windowSize))
    
    startTime = datetime.strptime(start, '%Y-%m-%d %H')
    stopTime = datetime.strptime("2011-01-10 00:00:00", '%Y-%m-%d %H:%M:%S')
    
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)
    
    #Instantiate empty arrays for the calculated values
    records = []

    numberOfIcmpPackets = []

    #Instantiate counter variable
    i = 0
    
    #Loop through all the flow records
    for rec in infile:
        if rec.stime >= stopTime:
            break
        if rec.stime <= startTime:
            continue
        if rec.stime >= startTime + interval:
            packets = numberOfPackets(records)
            
            #Find the number of ICMP packets in this time interval
            numberOfIcmpPackets.append(packets)

            if i >= windowSize:
                if abs(numberOfIcmpPackets[i] - np.nanmean(numberOfIcmpPackets[i-windowSize: i-1])) > 100:
                    f.write("\n" + str(startTime) + "," + str(abs(numberOfIcmpPackets[i] - np.nanmean(numberOfIcmpPackets[i-windowSize: i-1]))) + "," + str(numberOfIcmpPackets[i]) + "," + str(np.nanmean(numberOfIcmpPackets[i-windowSize: i-1])))
    
            #Reset the record aggregation
            records = []
            startTime = startTime + interval
            i+= 1
        records.append(rec)
    
    f.close()
    infile.close()

    
icmpDetection("/home/linneafg/silk-data/RawDataFromFilter/icmp-in-sorted.rw", "2011-01-03 00", timedelta(minutes = 1), 10)