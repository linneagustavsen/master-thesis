from pathlib import Path
from silk import *
from HelperFunctions.Distributions import *
from datetime import datetime,timedelta
import numpy as np

'''
    Calculates the number of ICMP destination unreachable packets in a flow and alerts in case of an anomaly
    Input:  silkFile:   string, file with flow records sorted on time
            start:      string, start time of detection 
            stop:       string, stop time of detection 
            systemId:   string, name of the system to calculate on
            frequency:  timedelta object, frequency of metric calculation
            interval:   timedelta object, size of the sliding window which the calculation is made on
            windowSize: int, represents a multiplier of frequency, how far back we want to compare the value with
            threshold:  int, values over this threshold will cause an alert
            attackDate: string, date of the attack the calculations are made on
'''
def icmpDstUnreachableDetection(silkFile, start, stop, systemId, frequency, interval, windowSize, threshold, attackDate):
    p = Path('Detections')
    q = p / 'Threshold' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    #Open file to write alerts to
    f = open(str(q) + "/ICMPDstUnreachable."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #Write the column titles to the files
    f.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    windowTime = startTime
    
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)
    
    #Instantiate empty arrays for the calculated values
    records = []

    numberOfIcmpDstUnreachablePackets = []

    #Instantiate variables
    i = 0
    sizes = []
    for rec in infile:
        if rec.etime >= stopTime:
            break
        if rec.stime < startTime:
            continue
        #Implement the sliding window
        if rec.stime > windowTime + frequency:
            lastSizes  = sum(sizes)
            thisMinuteSize = len(records) - lastSizes
            sizes.append(thisMinuteSize)
            windowTime += frequency
        if rec.stime > startTime + interval:
            #Find the number of ICMP Destination unavailable packets in this time interval
            numberOfIcmpDstUnreachablePackets.append(numberOfPackets(records))
            
            #If there is enough stored values to compare with we compare the difference of the metric with a threshold
            if i >= windowSize:
                if abs(numberOfIcmpDstUnreachablePackets[i] - np.nanmean(numberOfIcmpDstUnreachablePackets[i-windowSize: i-1])) > threshold:
                    f.write("\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(numberOfIcmpDstUnreachablePackets[i] - np.nanmean(numberOfIcmpDstUnreachablePackets[i-windowSize: i-1]))) + "," + str(numberOfIcmpDstUnreachablePackets[i]) + "," + str(np.nanmean(numberOfIcmpDstUnreachablePackets[i-windowSize: i-1])))

           #Push the sliding window
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1
 
        records.append(rec)

    infile.close()
    f.close()


#icmpDstUnreachableDetection("/home/linneafg/silk-data/RawDataFromFilter/icmp3-in-sorted.rw", "2011-01-03 00:00:00", "2011-01-10 00:00:00", "oslo-gw", timedelta(minutes = 1), 10, 50, "10.01")