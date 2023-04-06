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
            thresholdDstEntropy:            float, values over this threshold will cause an alert
            thresholdDstEntropyRate:        float, values over this threshold will cause an alert
            attackDate:                     string, date of the attack the calculations are made on
'''
def detectionDst(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdDstEntropy, thresholdDstEntropyRate, attackDate):
    #Open file to write alerts to
    dstEntropyFile = open("Detections/Entropy/NetFlow/DestinationIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    dstEntropyRateFile = open("Detections/Entropy/NetFlow/DestinationIPEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    dstEntropyFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    dstEntropyRateFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    
    #Makes a datetime object of the input start time
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    windowTime = startTime

    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    records = []

    ipDstArray = []
    ipDstRateArray = []

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
            #Find the probability distribution based on how many packets there is in each destination flow in this time interval
            PiDIP, nd = ipDestinationDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropyDip = generalizedEntropy(10,PiDIP)
            ipDstArray.append(entropyDip)
            #Calculate the generalized entropy rate of this distribution
            ipDstRateArray.append(entropyDip/nd)
            
            #If there is enough stored values to compare with we compare the difference of each metric with a threshold
            if i >=windowSize:
                if abs(ipDstArray[i] - np.nanmean(ipDstArray[i-windowSize: i-1])) > thresholdDstEntropy:
                    dstEntropyFile.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(ipDstArray[i] - np.nanmean(ipDstArray[i-windowSize: i-1]))) + "," + str(ipDstArray[i]) + "," + str(np.nanmean(ipDstArray[i-windowSize: i-1])))

                if abs(ipDstRateArray[i] - np.nanmean(ipDstRateArray[i-windowSize: i-1])) >  thresholdDstEntropyRate:
                    dstEntropyRateFile.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(ipDstRateArray[i] - np.nanmean(ipDstRateArray[i-windowSize: i-1]))) + "," + str(ipDstRateArray[i]) + "," + str(np.nanmean(ipDstRateArray[i-windowSize: i-1])))

            #Reset the record aggregation
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1

        records.append(rec)
    

    dstEntropyFile.close()
    dstEntropyRateFile.close()
    
    infile.close()
    