'''
How to get the flows in a file format:

    #Filter out all flows from a time period
    rwfilter --start-date=2011/01/03:00 --end-date=2011/01/10:00 --all-destination=/home/linneafg/silk-data/RawDataFromFilter/one-week-2011-01-03_03-10.rw --data-rootdir=/home/linneafg/silk-data/oslo-gw

    #Sorts them by start time
    rwsort --fields=stime --output-path=/home/linneafg/silk-data/RawDataFromFilter/one-week-2011-01-03_03-10-sorted.rw /home/linneafg/silk-data/RawDataFromFilter/one-week-2011-01-03_03-10.rw

'''

from silk import *
from HelperFunctions.DistributionsHistoric import *
from HelperFunctions.GeneralizedEntropy import *
import TrainDistributions as td
from datetime import datetime,timedelta
from IsAttackFlow import *
import pickle
'''

    Calculates entropy and other metrics and write them to file. Also checks if the flow is an attack flow
    Input:  File with flow records sorted on time, 
            start time as a string, 
            an aggregation interval as a timedelta object, 
            a window size of how far back we should compare the values
'''

def metricCalculation(silkFile, start, stop, frequency, interval):
    #Open file to write alerts to
    calculations = open("NetFlow/HistoricEntropy/Calculations/Metrics.attack.08.03.csv", "a")
    attackFlows = open("NetFlow/HistoricEntropy/Calculations/AttackFlows.attack.08.03.csv", "a")

    #Write the column titles to the files
    calculations.write("Time, srcEntropy, dstEntropy, flowEntropy")
    attackFlows.write("sTime, eTime")

    '''pickle_file_numberOfPacketsPerBiDirFlow = open("NetFlow/HistoricEntropy/Distributions/numberOfPacketsPerBiDirFlow.pkl", "rb")
    numberOfPacketsPerBiDirFlow = pickle.load(pickle_file_numberOfPacketsPerBiDirFlow)
    pickle_file_BiDirFlows = open("NetFlow/HistoricEntropy/Distributions/BiDirFlows.pkl", "rb")
    BiDirFlows = pickle.load(pickle_file_BiDirFlows)
    pickle_file_SumOfPacketsBiDirFlow = open("NetFlow/HistoricEntropy/Distributions/SumOfPacketsBiDirFlow.pkl", "rb")
    SumOfPacketsBiDirFlow = pickle.load(pickle_file_SumOfPacketsBiDirFlow)

    pickle_file_numberOfPacketsPerUniDirFlow = open("NetFlow/HistoricEntropy/Distributions/numberOfPacketsPerUniDirFlow.pkl", "rb")
    numberOfPacketsPerUniDirFlow = pickle.load(pickle_file_numberOfPacketsPerUniDirFlow)
    pickle_file_UniDirFlows = open("NetFlow/HistoricEntropy/Distributions/UniDirFlows.pkl", "rb")
    UniDirFlows = pickle.load(pickle_file_UniDirFlows)
    pickle_file_SumOfPacketsUniDirFlow = open("NetFlow/HistoricEntropy/Distributions/SumOfPacketsUniDirFlow.pkl", "rb")
    SumOfPacketsUniDirFlow = pickle.load(pickle_file_SumOfPacketsUniDirFlow)

    pickle_file_numberOfPacketsPerDstIP = open("NetFlow/HistoricEntropy/Distributions/numberOfPacketsPerDstIP.pkl", "rb")
    numberOfPacketsPerDstIP = pickle.load(pickle_file_numberOfPacketsPerDstIP)
    pickle_file_SumOfPacketsDstIP = open("NetFlow/HistoricEntropy/Distributions/SumOfPacketsDstIP.pkl", "rb")
    SumOfPacketsDstIP = pickle.load(pickle_file_SumOfPacketsDstIP)

    pickle_file_numberOfPacketsPerSrcIP = open("NetFlow/HistoricEntropy/Distributions/numberOfPacketsPerSrcIP.pkl", "rb")
    numberOfPacketsPerSrcIP = pickle.load(pickle_file_numberOfPacketsPerSrcIP)
    pickle_file_SumOfPacketsSrcIP = open("NetFlow/HistoricEntropy/Distributions/SumOfPacketsSrcIP.pkl", "rb")
    SumOfPacketsSrcIP = pickle.load(pickle_file_SumOfPacketsSrcIP)'''

   
    #Makes a datetime object of the input start time
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    windowTime = startTime
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    numberOfPacketsPerBiDirFlow, BiDirFlows,SumOfPacketsBiDirFlow = td.trainFlowDistribution(infile)
    infile = silkfile_open(silkFile, READ)

    numberOfPacketsPerDstIP,SumOfPacketsDstIP = td.trainIpDestinationDistribution(infile)
    infile = silkfile_open(silkFile, READ)

    numberOfPacketsPerSrcIP,SumOfPacketsSrcIP = td.trainIpSourceDistribution(infile)
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    records = []
    
    ipSrcArray = []

    ipDstArray = []

    flowArray = []
    #Instantiate counter variable
    i = 0
    sizes = []
    lastMinuteSize = 0
    print("start for loop")
    print(len(numberOfPacketsPerBiDirFlow))
    print(len(BiDirFlows))
    print(SumOfPacketsBiDirFlow)
    print(len(numberOfPacketsPerDstIP))
    print(SumOfPacketsDstIP)
    print(len(numberOfPacketsPerSrcIP))
    print(SumOfPacketsSrcIP)
    #Loop through all the flow records in the input file
    for rec in infile:
        

        if rec.etime >= stopTime:
            break
        if rec.stime < startTime:
            continue
        #Aggregate flows into the specified time interval
        if rec.stime >= startTime + interval:
            #Find the probability distribution based on how many packets there is in each source flow in this time interval
            PiSIP, ns, numberOfPacketsPerSrcIP, SumOfPacketsSrcIP = ipSourceDistribution(records,numberOfPacketsPerSrcIP, SumOfPacketsSrcIP)
            #Calculate the generalized entropy of this distribution
            entropySip = generalizedEntropy(10,PiSIP)
            ipSrcArray.append(entropySip)

            #Find the probability distribution based on how many packets there is in each destination flow in this time interval
            PiDIP, nd, numberOfPacketsPerDstIP, SumOfPacketsDstIP = ipDestinationDistribution(records,numberOfPacketsPerDstIP, SumOfPacketsDstIP)
            #Calculate the generalized entropy of this distribution
            entropyDip = generalizedEntropy(10,PiDIP)
            ipDstArray.append(entropyDip)
            
            #Find the probability distribution based on how many packets there is in each bi-directional flow in this time interval
            PiF, nf, numberOfPacketsPerBiDirFlow, BiDirFlows, SumOfPacketsBiDirFlow = flowDistribution(records, numberOfPacketsPerBiDirFlow, BiDirFlows, SumOfPacketsBiDirFlow)
            #Calculate the generalized entropy of this distribution
            entropyFlow = generalizedEntropy(10, PiF)
            flowArray.append(entropyFlow)

            
            calculations.write("\n" + str(startTime) + "," + str(ipSrcArray[i])  + "," + str(ipDstArray[i]) + "," + str(flowArray[i]))
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
    
    calculations.close()
    attackFlows.close()
     

    infile.close()
    
metricCalculation("/home/linneafg/silk-data/RawDataFromFilter/one-day-2011-01-10_11-sorted.rw", "2011-01-10 00:00:00", "2011-01-11 00:00:00",timedelta(minutes = 1), timedelta(minutes = 5))