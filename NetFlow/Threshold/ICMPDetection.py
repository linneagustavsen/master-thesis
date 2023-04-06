from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime,timedelta
import numpy as np

'''
    Calculates entropy and other metrics and alerts in case of an anomaly
    Input:  silkFile:                       string, File with flow records sorted on time
            start:                          string, indicating the start time of the data wanted
            stop:                           string, indicating the stop time of the data wanted
            systemId:                       string, name of the system to collect and calculate on
            frequency:                      timedelta object, frequency of metric calculation
            interval:                       timedelta object, size of the sliding window which the calculation is made on
            windowSize:                     int, represents a multiplier of frequency, how far back we want to compare the value with
            thresholdICMPRatio:             float, values over this threshold will cause an alert
            thresholdNumberOfICMPPackets:   int, values over this threshold will cause an alert
            attackDate:                     string, date of the attack the calculations are made on
'''
def detectionICMP(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdICMPRatio, thresholdNumberOfICMPPackets, attackDate):
    #Open file to write alerts to
    icmpRatioFile = open("Detections/Threshold/NetFlow/ICMPRatio."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    icmpPacketsFile = open("Detections/Threshold/NetFlow/ICMPPackets."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    
    #Write the column titles to the files
    icmpRatioFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    icmpPacketsFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    
    #Makes a datetime object of the input start time
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    windowTime = startTime

    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    records = []

    icmpRatioArray = []
    icmpPacketsArray = []

    #Instantiate counter variable
    i = 0
    sizes = []

    #Loop through all the flow records in the input file
    for rec in infile:
        if rec.etime >= stopTime:
            break
        if rec.stime < startTime:
            continue
        if rec.stime > windowTime + frequency:
            lastSizes = 0
            for size in sizes:
                lastSizes += size
            thisMinuteSize = len(records) - lastSizes
            sizes.append(thisMinuteSize)
            windowTime += frequency
        #Aggregate flows into the specified time interval
        if rec.stime >= startTime + interval:
            #Find the ratio of ICMP packets in this time interval
            icmpRatio, icmpPackets = icmpDistribution(records)
            icmpRatioArray.append(icmpRatio)
            icmpPacketsArray.append(icmpPackets)
            
            #If there is enough stored values to compare with we compare the difference of each metric with a threshold
            if i >=windowSize:
                if abs(icmpRatioArray[i] - np.nanmean(icmpRatioArray[i-windowSize: i-1])) > thresholdICMPRatio:
                    icmpRatioFile.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(icmpRatioArray[i] - np.nanmean(icmpRatioArray[i-windowSize: i-1]))) + "," + str(icmpRatioArray[i]) + "," + str(np.nanmean(icmpRatioArray[i-windowSize: i-1])))
                
                if abs(icmpPackets[i] - np.nanmean(icmpPackets[i-windowSize: i-1])) > thresholdNumberOfICMPPackets:
                    icmpPacketsFile.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(icmpPackets[i] - np.nanmean(icmpPackets[i-windowSize: i-1]))) + "," + str(icmpPackets[i]) + "," + str(np.nanmean(icmpPackets[i-windowSize: i-1])))
                
            #Reset the record aggregation
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1

        records.append(rec)
    
    icmpRatioFile.close()
    icmpPacketsFile.close()

    infile.close()
    