'''
How to get the flows in a file format:
    #Get icmp packets with destination AS 224 in the oslo-gw:
	rwfilter --start-date=2011/01/03:00 --end-date=2011/01/10:00 --proto=6,56 --flags-all=S/SA --pass-destination=/home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in.rw --data-rootdir=/home/linneafg/silk-data/oslo-gw
	
    #Sorts them by start time
	rwsort --fields=stime --output-path=/home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in-sorted.rw  /home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in.rw 

'''


from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime, timedelta
import numpy as np

'''

    Calculates entropy alerts in case of an anomaly
    Input:  File with flow records sorted on time, 
            start time as a string, 
            a aggregation interval as a timedelta object, 
            a window size of how far back we should compare the values
'''

def synDetection(silkFile, start, interval, windowSize):
    #Open file to write alerts to
    srcEntropyFile = open("EntropyNetFlow/Detections/SYNSourceIPEntropy.txt", "a")
    dstEntropyFile = open("EntropyNetFlow/Detections/SYNDestinationIPEntropy.txt", "a")
    flowEntropyFile = open("EntropyNetFlow/Detections/SYNFlowIPEntropy.txt", "a")

    #Write the column titles to the files
    srcEntropyFile.write("Time, Change, Value, Mean of the last "+ str(windowSize))
    dstEntropyFile.write("Time, Change, Value, Mean of the last"+ str(windowSize))
    flowEntropyFile.write("Time, Change, Value, Mean of the last"+ str(windowSize))
    
    #Makes a datetime object of the input start time
    startTime = datetime.strptime(start, '%Y-%m-%d %H')
    
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    records = []
    entropyOfSynPacketsPerSrc = []
    entropyOfSynPacketsPerDst = []
    entropyOfSynPacketsPerFlow = []

    i = 0
    #Loop through all the flow records in the input file
    for rec in infile:
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
                if abs(entropyOfSynPacketsPerSrc[i] - np.nanmean(entropyOfSynPacketsPerSrc[i-windowSize: i-1])) > 1:
                    srcEntropyFile.write("\n" + str(startTime) + "," + str(abs(entropyOfSynPacketsPerSrc[i] - np.nanmean(entropyOfSynPacketsPerSrc[i-windowSize: i-1]))) + "," + str(entropyOfSynPacketsPerSrc[i]) + "," + str(np.nanmean(entropyOfSynPacketsPerSrc[i-windowSize: i-1])))
                
                if abs(entropyOfSynPacketsPerDst[i] - np.nanmean(entropyOfSynPacketsPerDst[i-windowSize: i-1])) > 1:
                    dstEntropyFile.write("\n" + str(startTime) + "," + str(abs(entropyOfSynPacketsPerDst[i] - np.nanmean(entropyOfSynPacketsPerDst[i-windowSize: i-1]))) + "," + str(entropyOfSynPacketsPerDst[i]) + "," + str(np.nanmean(entropyOfSynPacketsPerDst[i-windowSize: i-1])))

                if abs(entropyOfSynPacketsPerFlow[i] - np.nanmean(entropyOfSynPacketsPerFlow[i-windowSize: i-1])) > 1:
                    flowEntropyFile.write("\n" + str(startTime) + "," + str(abs(entropyOfSynPacketsPerFlow[i] - np.nanmean(entropyOfSynPacketsPerFlow[i-windowSize: i-1]))) + "," + str(entropyOfSynPacketsPerFlow[i]) + "," + str(np.nanmean(entropyOfSynPacketsPerFlow[i-windowSize: i-1])))

            #Reset the record aggregation
            records = []
            startTime = startTime + interval
            i+= 1
        records.append(rec)
            

    infile.close()
    srcEntropyFile.close()
    dstEntropyFile.close()
    flowEntropyFile.close()

synDetection("/home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in-sorted.rw", "2011-01-03 00",timedelta(minutes = 1), 10)