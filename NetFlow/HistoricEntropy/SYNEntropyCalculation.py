'''
How to get the flows in a file format:
    #Get SYN packets with destination AS 224 in the oslo-gw:
	rwfilter --start-date=2011/01/03:00 --end-date=2011/01/10:00 --proto=6,56 --flags-all=S/SA --pass-destination=/home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in.rw --data-rootdir=/home/linneafg/silk-data/oslo-gw
	
    #Sorts them by start time
	rwsort --fields=stime --output-path=/home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in-sorted.rw  /home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in.rw 

'''


from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime, timedelta
from IsAttackFlow import *

'''

    Calculates entropy
    Input:  File with flow records sorted on time, 
            start time as a string, 
            a aggregation interval as a timedelta object, 
            a window size of how far back we should compare the values
'''

def synEntropyCalculation(silkFile, start, stop, frequency, interval, windowSize):
    #Open file to write alerts to
    calculations = open("NetFlow/Entropy/Calculations/SYN.attack.08.03.csv", "a")
    attackFlows = open("NetFlow/Entropy/Calculations/AttackFlowsSYN.attack.08.03.csv", "a")

    #Write the column titles to the files
    calculations.write("Time, srcEntropy, dstEntropy, flowEntropy")
    attackFlows.write("sTime, eTime")
    
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
            
            calculations.write("\n" + str(startTime) + "," + str(entropyOfSynPacketsPerSrc[i]) + "," + str(entropyOfSynPacketsPerDst[i]) + "," + str(entropyOfSynPacketsPerFlow[i]))
            #Reset the record aggregation
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1
        if isAttackFlow(rec.sip, rec.dip):
            attackFlows.write("\n" + str(rec.stime) + ","+ str(rec.etime))
        if rec.stime >= windowTime + frequency:
            thisMinuteSize = len(records) - lastMinuteSize
            sizes.append(thisMinuteSize)
            lastMinuteSize = thisMinuteSize
            windowTime += frequency
        records.append(rec)
            

    infile.close()
    calculations.close()
    attackFlows.close()

synEntropyCalculation("/home/linneafg/silk-data/RawDataFromFilter/one-day-tcp-syn-sorted.rw", "2011-01-10 00:00:00", "2011-01-11 00:00:00",timedelta(minutes = 1), timedelta(minutes = 5), 10)