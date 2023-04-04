from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime
import numpy as np

'''
    Calculates entropy and alerts in case of an anomaly
    Input:  silkFile:       string, File with flow records sorted on time
            start:          string, indicating the start time of the data wanted
            stop:           string, indicating the stop time of the data wanted
            systemId:       string, name of the system to collect and calculate on
            frequency:      timedelta object, frequency of metric calculation
            interval:       timedelta object, size of the sliding window which the calculation is made on
            windowSize:     int, represents a multiplier of frequency, how far back we want to compare the value with
            thresholdSrc:   float, values over this threshold will cause an alert
            thresholdDst:   float, values over this threshold will cause an alert
            thresholdFlow:  float, values over this threshold will cause an alert
            attackDate:     string, date of the attack the calculations are made on
'''
def synDetection(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdSrc, thresholdDst, thresholdFlow, attackDate):
    #Open file to write alerts to
    srcEntropyFile = open("Detections/Entropy/NetFlow/SYNSourceIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    dstEntropyFile = open("Detections/Entropy/NetFlow/SYNDestinationIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    flowEntropyFile = open("Detections/Entropy/NetFlow/SYNFlowIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    srcEntropyFile.write("Time,Change,Value,Mean of the last "+ str(windowSize))
    dstEntropyFile.write("Time,Change,Value,Mean of the last"+ str(windowSize))
    flowEntropyFile.write("Time,Change,Value,Mean of the last"+ str(windowSize))
    
    #Makes a datetime object of the input start time
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    windowTime = startTime
    
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    records = []
    entropyOfSynPacketsPerSrc = []
    entropyOfSynPacketsPerDst = []
    entropyOfSynPacketsPerFlow = []

    i = 0
    sizes = []
    lastMinuteSize = 0
    #Loop through all the flow records in the input file
    for rec in infile:
        if rec.etime >= stopTime:
            break
        if rec.stime < startTime:
            continue
        #Aggregate flows into the specified time interval
        if rec.stime >= startTime + interval:
            #Find the probability distribution based on how many SYN packets there is in each source flow in this time interval
            PiSIP, ns = ipSourceDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropySip = generalizedEntropy(10,PiSIP)
            entropyOfSynPacketsPerSrc.append(entropySip)

            #Find the probability distribution based on how many SYN packets there is in each destination flow in this time interval
            PiDIP, nd = ipDestinationDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropyDip = generalizedEntropy(10,PiDIP)
            entropyOfSynPacketsPerDst.append(entropyDip)

            #Find the probability distribution based on how many SYN packets there is in each bi-directional flow in this time interval
            PiF, nf = uniDirFlowDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropyFlow = generalizedEntropy(10,PiF)
            entropyOfSynPacketsPerFlow.append(entropyFlow)
            
            #If there is enough stored values to compare with we compare the difference of each metric with a threshold
            if i >=windowSize:
                if abs(entropyOfSynPacketsPerSrc[i] - np.nanmean(entropyOfSynPacketsPerSrc[i-windowSize: i-1])) > thresholdSrc:
                    srcEntropyFile.write("\n" + str(startTime) + "," + str(abs(entropyOfSynPacketsPerSrc[i] - np.nanmean(entropyOfSynPacketsPerSrc[i-windowSize: i-1]))) + "," + str(entropyOfSynPacketsPerSrc[i]) + "," + str(np.nanmean(entropyOfSynPacketsPerSrc[i-windowSize: i-1])))
                
                if abs(entropyOfSynPacketsPerDst[i] - np.nanmean(entropyOfSynPacketsPerDst[i-windowSize: i-1])) > thresholdDst:
                    dstEntropyFile.write("\n" + str(startTime) + "," + str(abs(entropyOfSynPacketsPerDst[i] - np.nanmean(entropyOfSynPacketsPerDst[i-windowSize: i-1]))) + "," + str(entropyOfSynPacketsPerDst[i]) + "," + str(np.nanmean(entropyOfSynPacketsPerDst[i-windowSize: i-1])))

                if abs(entropyOfSynPacketsPerFlow[i] - np.nanmean(entropyOfSynPacketsPerFlow[i-windowSize: i-1])) > thresholdFlow:
                    flowEntropyFile.write("\n" + str(startTime) + "," + str(abs(entropyOfSynPacketsPerFlow[i] - np.nanmean(entropyOfSynPacketsPerFlow[i-windowSize: i-1]))) + "," + str(entropyOfSynPacketsPerFlow[i]) + "," + str(np.nanmean(entropyOfSynPacketsPerFlow[i-windowSize: i-1])))

            #Reset the record aggregation
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1
        if rec.stime >= windowTime + frequency:
            thisMinuteSize = len(records) - lastMinuteSize
            sizes.append(thisMinuteSize)
            lastMinuteSize = thisMinuteSize
            windowTime += frequency
        records.append(rec)
            

    infile.close()
    srcEntropyFile.close()
    dstEntropyFile.close()
    flowEntropyFile.close()
