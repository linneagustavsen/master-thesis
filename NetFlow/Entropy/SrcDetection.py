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
            thresholdSrcEntropy:            float, values over this threshold will cause an alert
            thresholdSrcEntropyRate:        float, values over this threshold will cause an alert
            attackDate:                     string, date of the attack the calculations are made on
'''
def detectionSrc(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdSrcEntropy, thresholdSrcEntropyRate, attackDate):
    #Open file to write alerts to
    srcEntropyFile = open("Detections/Entropy/NetFlow/SourceIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    srcEntropyRateFile = open("Detections/Entropy/NetFlow/SourceIPEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    
    #Write the column titles to the files
    srcEntropyFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    srcEntropyRateFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))

    #Makes a datetime object of the input start time
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    windowTime = startTime

    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    records = []
    
    ipSrcArray = []
    ipSrcRateArray = []

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

            #Find the probability distribution based on how many packets there is in each source flow in this time interval
            PiSIP, ns = ipSourceDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropySip = generalizedEntropy(10,PiSIP)
            ipSrcArray.append(entropySip)
            #Calculate the generalized entropy rate of this distribution
            ipSrcRateArray.append(entropySip/ns)

            
            #If there is enough stored values to compare with we compare the difference of each metric with a threshold
            if i >=windowSize:
                if abs(ipSrcArray[i] - np.nanmean(ipSrcArray[i-windowSize: i-1])) > thresholdSrcEntropy:
                    srcEntropyFile.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(ipSrcArray[i] - np.nanmean(ipSrcArray[i-windowSize: i-1]))) + "," + str(ipSrcArray[i]) + "," + str(np.nanmean(ipSrcArray[i-windowSize: i-1])))
                
                if abs(ipSrcRateArray[i] - np.nanmean(ipSrcRateArray[i-windowSize: i-1])) > thresholdSrcEntropyRate:
                    srcEntropyRateFile.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(ipSrcRateArray[i] - np.nanmean(ipSrcRateArray[i-windowSize: i-1]))) + "," + str(ipSrcRateArray[i]) + "," + str(np.nanmean(ipSrcRateArray[i-windowSize: i-1])))

            #Reset the record aggregation
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1

        records.append(rec)
    
           
    srcEntropyFile.close()
    srcEntropyRateFile.close()

    infile.close()
    