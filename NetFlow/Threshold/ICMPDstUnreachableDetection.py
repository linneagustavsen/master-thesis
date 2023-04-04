from silk import *
from HelperFunctions.Distributions import *
from datetime import datetime,timedelta
import numpy as np

'''
    Calculates the number of ICMP destination unreachable packets in a flow and alerts in case of an anomaly
    Input:  silkFile:   string, File with flow records sorted on time
            start:      string, start time of detection 
            stop:       string, stop time of detection 
            systemId:   string, name of the system to calculate on
            frequency:  timedelta object, frequency of metric calculation,
            windowSize: int, represents a multiplier of frequency, how far back we want to compare the value with
            threshold:  int, values over this threshold will cause an alert
            attackDate: string, date of the attack the calculations are made on
'''
def icmpDstUnreachableDetection(silkFile, start, stop, systemId, frequency, windowSize, threshold, attackDate):
    #Open file to write alerts to
    f = open("NetFlow/Threshold/Detections/ICMPDstUnreachable.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #Write the column titles to the files
    f.write("Time,Change,Value,Mean of the last "+ str(windowSize))
    
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)
    
    #Instantiate empty arrays for the calculated values
    records = []

    numberOfIcmpDstUnreachablePackets = []

    #Instantiate counter variable
    i = 0
   
    for rec in infile:
        if rec.etime >= stopTime:
            break
        if rec.stime < startTime:
            continue
        if rec.stime >= startTime + frequency:
            
            #Find the number of ICMP Destination unavailable packets in this time frequency
            numberOfIcmpDstUnreachablePackets.append(numberOfPackets(records))
            
            #If there is enough stored values to compare with we compare the difference of the metric with a threshold
            if i >= windowSize:
                if abs(numberOfIcmpDstUnreachablePackets[i] - np.nanmean(numberOfIcmpDstUnreachablePackets[i-windowSize: i-1])) > threshold:
                    f.write("\n" + str(startTime) + "," + str(abs(numberOfIcmpDstUnreachablePackets[i] - np.nanmean(numberOfIcmpDstUnreachablePackets[i-windowSize: i-1]))) + "," + str(numberOfIcmpDstUnreachablePackets[i]) + "," + str(np.nanmean(numberOfIcmpDstUnreachablePackets[i-windowSize: i-1])))

            #Reset the record aggregation
            records = []
            startTime = startTime + frequency
            i += 1
        records.append(rec)

    infile.close()
    f.close()


icmpDstUnreachableDetection("/home/linneafg/silk-data/RawDataFromFilter/icmp3-in-sorted.rw", "2011-01-03 00:00:00", "2011-01-10 00:00:00", "oslo-gw", timedelta(minutes = 1), 10, 50, "10.01")