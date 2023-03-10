'''
How to get the flows in a file format:

	#Get icmp packets with type "destination unreachable"
	rwfilter --start-date=2011/01/03:00 --end-date=2011/01/10:00 --proto=1,58 --icmp-type=3 --pass-destination=/home/linneafg/silk-data/RawDataFromFilter/icmp3-in.rw --data-rootdir=/home/linneafg/silk-data/oslo-gw

    #Sorts them by start time
    rwsort --fields=stime --output-path=/home/linneafg/silk-data/RawDataFromFilter/icmp3-in-sorted.rw /home/linneafg/silk-data/RawDataFromFilter/icmp3-in.rw

'''

from silk import *
from NumberOfPackets import *
from datetime import datetime,timedelta
import numpy as np

'''

    Calculates the number of ICMP destination unreachable packets and alerts in case of an anomaly
    Input:  File with flow records sorted on time, 
            start time as a string, 
            a aggregation interval as a timedelta object, 
            a window size of how far back we should compare the values
'''

def icmpDstUnreachableDetection(silkFile, start, interval, windowSize):
    #Open file to write alerts to
    f = open("NetFlow/Threshold/Detections/ICMPDstUnreachable.csv", "a")
    #Write the column titles to the files
    f.write("Time, Change, Value, Mean of the last "+ str(windowSize))
    
    startTime = datetime.strptime(start, '%Y-%m-%d %H')
    stopTime = datetime.strptime("2011-01-10 00:00:00", '%Y-%m-%d %H:%M:%S')
    
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)
    
    #Instantiate empty arrays for the calculated values
    records = []

    numberOfIcmpDstUnreachablePackets = []

    #Instantiate counter variable
    i = 0
   
    for rec in infile:
        if rec.stime >= stopTime:
            break
        if rec.stime <= startTime:
            continue
        if rec.stime >= startTime + interval:
            
            #Find the number of ICMP Destination unavailable packets in this time interval
            numberOfIcmpDstUnreachablePackets.append(numberOfPackets(records))
            
            #If there is enough stored values to compare with we compare the difference of the metric with a threshold
            if i >= windowSize:
                if abs(numberOfIcmpDstUnreachablePackets[i] - np.nanmean(numberOfIcmpDstUnreachablePackets[i-windowSize: i-1])) > 50:
                    f.write("\n" + str(startTime) + "," + str(abs(numberOfIcmpDstUnreachablePackets[i] - np.nanmean(numberOfIcmpDstUnreachablePackets[i-windowSize: i-1]))) + "," + str(numberOfIcmpDstUnreachablePackets[i]) + "," + str(np.nanmean(numberOfIcmpDstUnreachablePackets[i-windowSize: i-1])))

            #Reset the record aggregation
            records = []
            startTime = startTime + interval
            i += 1
        records.append(rec)
        

    infile.close()
    f.close()


icmpDstUnreachableDetection("/home/linneafg/silk-data/RawDataFromFilter/icmp3-in-sorted.rw", "2011-01-03 00", timedelta(minutes = 1), 10)