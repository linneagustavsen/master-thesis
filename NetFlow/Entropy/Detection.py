'''
How to get the flows in a file format:

    #Filter out all flows from a time period
    rwfilter --start-date=2011/01/03:00 --end-date=2011/01/10:00 --all-destination=/home/linneafg/silk-data/RawDataFromFilter/one-week-2011-01-03_03-10.rw --data-rootdir=/home/linneafg/silk-data/oslo-gw

    #Sorts them by start time
    rwsort --fields=stime --output-path=/home/linneafg/silk-data/RawDataFromFilter/one-week-2011-01-03_03-10-sorted.rw /home/linneafg/silk-data/RawDataFromFilter/one-week-2011-01-03_03-10.rw

'''

from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from ICMPRatio import *
from datetime import datetime,timedelta
import numpy as np

'''

    Calculates entropy and other metrics and alerts in case of an anomaly
    Input:  File with flow records sorted on time, 
            start time as a string, 
            a aggregation interval as a timedelta object, 
            a window size of how far back we should compare the values
'''

def detection(silkFile, start, interval, windowSize):
    #Open file to write alerts to
    srcEntropyFile = open("NetFlow/Entropy/Detections/SourceIPEntropy.csv", "a")
    srcEntropyRateFile = open("NetFlow/Entropy/Detections/SourceIPEntropyRate.csv", "a")
    dstEntropyFile = open("NetFlow/Entropy/Detections/DestinationIPEntropy.csv", "a")
    dstEntropyRateFile = open("NetFlow/Entropy/Detections/DestinationIPEntropyRate.csv", "a")
    flowEntropyFile = open("NetFlow/Entropy/Detections/FlowEntropy.csv", "a")
    flowEntropyRateFile = open("NetFlow/Entropy/Detections/FlowEntropyRate.csv", "a")
    flowFile = open("NetFlow/Threshold/Detections/NumberOfFlows.csv", "a")
    icmpRatioFile = open("NetFlow/Threshold/Detections/ICMPRatio.csv", "a")

    #Write the column titles to the files
    srcEntropyFile.write("Time, Change, Value, Mean of the last "+ str(windowSize))
    srcEntropyRateFile.write("Time, Change, Value, Mean of the last "+ str(windowSize))
    dstEntropyFile.write("Time, Change, Value, Mean of the last "+ str(windowSize))
    dstEntropyRateFile.write("Time, Change, Value, Mean of the last "+ str(windowSize))
    flowEntropyFile.write("Time, Change, Value, Mean of the last "+ str(windowSize))
    flowEntropyRateFile.write("Time, Change, Value, Mean of the last "+ str(windowSize))
    flowFile.write("Time, Change, Value, Mean of the last "+ str(windowSize))
    icmpRatioFile.write("Time, Change, Value, Mean of the last "+ str(windowSize))

    #Makes a datetime object of the input start time
    startTime = datetime.strptime(start, '%Y-%m-%d %H')
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    records = []
    
    ipSrcArray = []
    ipSrcRateArray = []

    ipDstArray = []
    ipDstRateArray = []

    flowArray = []
    flowRateArray = []

    numberOfFlows = []

    icmpRatioArray = []
    #Instantiate counter variable
    i = 0

    #Loop through all the flow records in the input file
    for rec in infile:
        #Aggregate flows into the specified time interval
        if rec.stime >= startTime + interval:

            #Find the probability distribution based on how many packets there is in each source flow in this time interval
            PiSIP, ns = ipSourceDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropySip = generalizedEntropy(10,PiSIP)
            ipSrcArray.append(entropySip)
            #Calculate the generalized entropy rate of this distribution
            ipSrcRateArray.append(entropySip/ns)

            #Find the probability distribution based on how many packets there is in each destination flow in this time interval
            PiDIP, nd = ipDestinationDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropyDip = generalizedEntropy(10,PiDIP)
            ipDstArray.append(entropyDip)
            #Calculate the generalized entropy rate of this distribution
            ipDstRateArray.append(entropyDip/nd)
            
            #Find the probability distribution based on how many packets there is in each bi-directional flow in this time interval
            PiF, nf = flowDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropyFlow = generalizedEntropy(10, PiF)
            flowArray.append(entropyFlow)
            #Calculate the generalized entropy rate of this distribution
            flowRateArray.append(entropyFlow/nf)

            #Store the number of bi-directional flows in this time interval
            numberOfFlows.append(nf)

            #Find the ratio of ICMP packets in this time interval
            icmpRatioArray.append(icmpRatio(records))
            
            #If there is enough stored values to compare with we compare the difference of each metric with a threshold
            if i >=windowSize:
                if abs(ipSrcArray[i] - np.nanmean(ipSrcArray[i-windowSize: i-1])) > 1:
                    srcEntropyFile.write("\n" + str(startTime) + "," + str(abs(ipSrcArray[i] - np.nanmean(ipSrcArray[i-windowSize: i-1]))) + "," + str(ipSrcArray[i]) + "," + str(np.nanmean(ipSrcArray[i-windowSize: i-1])))
                
                if abs(ipSrcRateArray[i] - np.nanmean(ipSrcRateArray[i-windowSize: i-1])) > 0.0001:
                    srcEntropyRateFile.write("\n" + str(startTime) + "," + str(abs(ipSrcRateArray[i] - np.nanmean(ipSrcRateArray[i-windowSize: i-1]))) + "," + str(ipSrcRateArray[i]) + "," + str(np.nanmean(ipSrcRateArray[i-windowSize: i-1])))
                
                if abs(ipDstArray[i] - np.nanmean(ipDstArray[i-windowSize: i-1])) > 1:
                    dstEntropyFile.write("\n" + str(startTime) + "," + str(abs(ipDstArray[i] - np.nanmean(ipDstArray[i-windowSize: i-1]))) + "," + str(ipDstArray[i]) + "," + str(np.nanmean(ipDstArray[i-windowSize: i-1])))

                if abs(ipDstRateArray[i] - np.nanmean(ipDstRateArray[i-windowSize: i-1])) >  0.0001:
                    dstEntropyRateFile.write("\n" + str(startTime) + "," + str(abs(ipDstRateArray[i] - np.nanmean(ipDstRateArray[i-windowSize: i-1]))) + "," + str(ipDstRateArray[i]) + "," + str(np.nanmean(ipDstRateArray[i-windowSize: i-1])))

                if abs(flowArray[i] - np.nanmean(flowArray[i-windowSize: i-1])) > 1:
                    flowEntropyFile.write("\n" + str(startTime) + "," + str(abs(flowArray[i] - np.nanmean(flowArray[i-windowSize: i-1]))) + "," + str(flowArray[i]) + "," + str(np.nanmean(flowArray[i-windowSize: i-1])))
                
                if abs(flowRateArray[i] - np.nanmean(flowRateArray[i-windowSize: i-1])) > 0.0001:
                    flowEntropyRateFile.write("\n" + str(startTime) + "," + str(abs(flowRateArray[i] - np.nanmean(flowRateArray[i-windowSize: i-1]))) + "," + str(flowRateArray[i]) + "," + str(np.nanmean(flowRateArray[i-windowSize: i-1])))
                
                if abs(numberOfFlows[i] - np.nanmean(numberOfFlows[i-windowSize: i-1])) > 10000:
                    flowFile.write("\n" + str(startTime) + "," + str(abs(numberOfFlows[i] - np.nanmean(numberOfFlows[i-windowSize: i-1]))) + "," + str(numberOfFlows[i]) + "," + str(np.nanmean(numberOfFlows[i-windowSize: i-1])))
                 
                if abs(icmpRatioArray[i] - np.nanmean(icmpRatioArray[i-windowSize: i-1])) > 0.001:
                    icmpRatioFile.write("\n" + str(startTime) + "," + str(abs(icmpRatioArray[i] - np.nanmean(icmpRatioArray[i-windowSize: i-1]))) + "," + str(icmpRatioArray[i]) + "," + str(np.nanmean(icmpRatioArray[i-windowSize: i-1])))
        
            #Reset the record aggregation
            records = []
            startTime = startTime + interval
            i+= 1
        records.append(rec)
    
           
    srcEntropyFile.close()
    srcEntropyRateFile.close()
    dstEntropyFile.close()
    dstEntropyRateFile.close()
    flowEntropyFile.close()
    flowEntropyRateFile.close()
    flowFile.close()
    icmpRatioFile.close()

    infile.close()
    
detection("/home/linneafg/silk-data/RawDataFromFilter/one-week-2011-01-03_03-10-sorted.rw", "2011-01-03 00",timedelta(minutes = 1), 10)