from silk import *
from HelperFunctions.Distributions import *
from datetime import datetime,timedelta
import numpy as np
import paho.mqtt.client as mqtt
import json
from HelperFunctions.IsAttack import isAttack
from HelperFunctions.Normalization import normalization

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
def icmpDstUnreachableDetection(silkFile, start, stop, frequency, interval, windowSize):
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    windowTime = startTime
    
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)
    
    #Instantiate empty arrays for the calculated values
    records = []

    numberOfIcmpDstUnreachablePackets = []

    maxICMP = 0
    minICMP = 1000000000000000000

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
            lastSizes = 0
            for size in sizes:
                lastSizes += size
            thisMinuteSize = len(records) - lastSizes
            sizes.append(thisMinuteSize)
            windowTime += frequency
        if rec.stime > startTime + interval:
            #Find the number of ICMP Destination unavailable packets in this time interval
            numberOfIcmpDstUnreachablePackets.append(numberOfPackets(records))
            
            #If there is enough stored values to compare with we compare the difference of the metric with a threshold
            if i >= windowSize:
                change = abs(numberOfIcmpDstUnreachablePackets[i] - np.nanmean(numberOfIcmpDstUnreachablePackets[i-windowSize: i-1]))
                if change > maxICMP:
                    maxICMP = change
                elif change < minICMP:
                    minICMP = change 
           #Push the sliding window
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1
 
        records.append(rec)
    infile.close()
    json_file = open("NetFlow/Entropy/Calculations/MinMax.icmp_dst_unreachable."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": minICMP, "maximum": maxICMP},json_file)
    json_file.close()
    json_file.close()

icmpDstUnreachableDetection("/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/icmpDstUnreachable-all7weeks-sorted.rw", "2010-12-27 00:00:00", "2011-02-14 00:00:00", timedelta(minutes = 1), timedelta(minutes = 10), 10)