import json
import pickle
from pathlib import Path
import numpy as np
from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime, timedelta
from HelperFunctions.IsAttack import *

'''
    Calculates entropy on TCP SYN packets and writes it to file
    Input:  
            silkFile:   string, file with flow records sorted on time
            start:      string, indicating the start time of the data wanted
            stop:       string, indicating the stop time of the data wanted
            systemId:   string, name of the system to collect and calculate on
            frequency:  timedelta object, frequency of metric calculation
            interval:   timedelta object, size of the sliding window which the calculation is made on
            attackDate: string, date of the attack the calculations are made on
'''
def findMinMaxSynEntropy(silkFile, start, stop, frequency, interval, windowSize):
    #Makes datetime objects of the input times
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

    changes_sip = []
    min_sip = 100000000000000

    changes_dip = []
    min_dip = 100000000000000

    changes_f = []
    min_f = 100000000000000

    i = 0
    sizes = []

    #Loop through all the flow records in the input file
    for rec in infile:
        if rec.etime > stopTime + frequency:
            continue
        if rec.stime < startTime:
            continue
        #Implement the sliding window
        if rec.stime > windowTime + frequency:
            lastSizes  = sum(sizes)
            thisMinuteSize = len(records) - lastSizes
            sizes.append(thisMinuteSize)
            windowTime += frequency
        #Aggregate flows into the specified time interval
        if rec.stime > startTime + interval:
            if len(records) == 0:
                startTime = startTime + frequency
                sizes.pop(0)
                records.append(rec)
                continue
            #Find the probability distribution based on how many SYN packets there is in each source flow in this time interval
            PiSIP, ns = ipSourceDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropySip = generalizedEntropy(10,PiSIP)
            entropyOfSynPacketsPerSrc.append(entropySip)
            #srcDistributionDict[rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ")] = PiSIP

            #Find the probability distribution based on how many SYN packets there is in each destination flow in this time interval
            PiDIP, nd = ipDestinationDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropyDip = generalizedEntropy(10,PiDIP)
            entropyOfSynPacketsPerDst.append(entropyDip)
            #dstDistributionDict[rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ")] = PiDIP

            #Find the probability distribution based on how many SYN packets there is in each bi-directional flow in this time interval
            PiF, nf = uniDirFlowDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropyFlow = generalizedEntropy(10,PiF)
            entropyOfSynPacketsPerFlow.append(entropyFlow)
            #flowDistributionDict[rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ")] = PiF
            if i >=windowSize:
                change_sip = abs(entropyOfSynPacketsPerSrc[i] - np.nanmean(entropyOfSynPacketsPerSrc[i-windowSize: i-1]))
                if change_sip < min_sip:
                    min_sip = change_sip
                changes_sip.append(change_sip)
                
                
                change_dip = abs(entropyOfSynPacketsPerDst[i] - np.nanmean(entropyOfSynPacketsPerDst[i-windowSize: i-1]))
                if change_dip < min_dip:
                    min_dip = change_dip
                changes_dip.append(change_dip)

                change_f = abs(entropyOfSynPacketsPerFlow[i] - np.nanmean(entropyOfSynPacketsPerFlow[i-windowSize: i-1]))
                if change_f < min_f:
                    min_f = change_f
                changes_f.append(change_f)
            #Push the sliding window
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1
    
        records.append(rec)
            

    infile.close()

    json_file = open("NetFlow/Entropy/Calculations/MinMaxValues/MinMax.SYN_src."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min_sip, "maximum": 3*np.nanmean(changes_sip)},json_file)
    json_file.close()


    json_file = open("NetFlow/Entropy/Calculations/MinMaxValues/MinMax.SYN_dst."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min_dip, "maximum": 3*np.nanmean(changes_dip)},json_file)
    json_file.close()


    json_file = open("NetFlow/Entropy/Calculations/MinMaxValues/MinMax.SYN_flow."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min_f, "maximum": 3*np.nanmean(changes_f)},json_file)
    json_file.close()

findMinMaxSynEntropy("/home/linneafg/silk-data/RawDataFromFilter/oslo-gw1/tcp-syn-all7weeks-sorted.rw", "2010-12-27 00:00:00", "2011-02-14 00:00:00", timedelta(minutes = 1), timedelta(minutes = 5), 10)
findMinMaxSynEntropy("/home/linneafg/silk-data/RawDataFromFilter/oslo-gw1/tcp-syn-all7weeks-sorted.rw", "2010-12-27 00:00:00", "2011-02-14 00:00:00", timedelta(minutes = 1), timedelta(minutes = 10), 10)
findMinMaxSynEntropy("/home/linneafg/silk-data/RawDataFromFilter/oslo-gw1/tcp-syn-all7weeks-sorted.rw", "2010-12-27 00:00:00", "2011-02-14 00:00:00", timedelta(minutes = 1), timedelta(minutes = 15), 10)
