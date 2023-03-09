'''
How to get the flows in a file format:

    #Get icmp packets with destination AS 224 in the oslo-gw:
	rwfilter --start-date=2011/01/03:00 --end-date=2011/01/10:00 --proto=6,56 --flags-all=S/SA --pass-destination=/home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in.rw --data-rootdir=/home/linneafg/silk-data/oslo-gw
	
    #Sorts them by start time
	rwsort --fields=stime --output-path=/home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in-sorted.rw  /home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in.rw 

'''

from silk import *
from datetime import datetime
import numpy as np

'''

    Calculates the number of SYN packets in a flow and alerts in case of an anomaly
    Input:  File with flow records sorted on time, 
            start time as a string, 
            a window size of how many flows back we should compare the values
'''

def synDetection(silkFile, start, windowSize):
    #Open file to write alerts to
    f = open("ThresholdNetFlow/Detections/TCPSYN.csv", "a")
    #Write the column titles to the files
    f.write("Time, Change, Value, Mean of the last "+ str(windowSize))

    startTime = datetime.strptime(start, '%Y-%m-%d %H')

    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    synPacketsPerFlow = []
    
    #Instantiate counter variable
    i = 0

    #Loop through all the flow records
    for rec in infile:
        synPacketsPerFlow.append(rec.packets)

        #If there is enough stored values to compare with we compare the difference of the metric with a threshold
        if i >= windowSize:
            if rec.packets >= 5:
                f.write("\n" + str(startTime) + "," + str(abs(synPacketsPerFlow[i] - np.nanmean(synPacketsPerFlow[i-windowSize: i-1]))) + "," + str(synPacketsPerFlow[i]) + "," + str(np.nanmean(synPacketsPerFlow[i-windowSize: i-1])))
        i += 1
    infile.close()

synDetection("/home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in-sorted.rw", "2011-01-03 00", 10)
