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
from datetime import datetime,timedelta
from .IsAttackFlow import *

'''

    Calculates entropy and other metrics and write them to file. Also checks if the flow is an attack flow
    Input:  File with flow records sorted on time, 
            start time as a string, 
            an aggregation interval as a timedelta object, 
            a window size of how far back we should compare the values
'''

def metricCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate):
    #Open file to write alerts to
    calculations = open("NetFlowCalculations/Entropy/Calculations/Metrics."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    attackFlows = open("NetFlowCalculations/Entropy/Calculations/AttackFlows."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    calculations.write("Time,srcEntropy,srcEntropyRate,dstEntropy,dstEntropyRate,flowEntropy,flowEntropyRate,numberOfFlows,icmpRatio,icmpPackets,packetSizeEntropy,packetSizeEntropyRate,numberOfPackets,numberOfBytes")
    attackFlows.write("sTime,eTime")


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

    ipDstArray = []
    ipDstRateArray = []

    flowArray = []
    flowRateArray = []

    numberOfFlows = []

    icmpRatioArray = []
    icmpPacketsArray = []
    packetSizeArray = []
    packetSizeRateArray = []
    packetNumberArray = []
    bytesArray = []
    #Instantiate counter variable
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
            icmpRatio, icmpPackets = icmpDistribution(records)
            icmpRatioArray.append(icmpRatio)
            icmpPacketsArray.append(icmpPackets)

             #Find the probability distribution based on how big the packets are this time interval
            PiPS,nd = packetSizeDistributionNetFlow(records)
            #Calculate the generalized entropy of this distribution
            entropyPacketSize = generalizedEntropy(10, PiPS)
            packetSizeArray.append(entropyPacketSize)

            #Calculate the generalized entropy rate of this distribution
            entropyRatePacketSize = entropyPacketSize/nd
            packetSizeRateArray.append(entropyRatePacketSize)

            #Store the number of packets and bytes this time interval
            packetNumberArray.append(numberOfPackets(records))
            bytesArray.append(numberOfBytes(records))

            calculations.write("\n" + str(startTime) + "," + str(ipSrcArray[i]) + "," + str(ipSrcRateArray[i]) 
                               + "," + str(ipDstArray[i]) + "," + str(ipDstRateArray[i]) + "," + str(flowArray[i]) 
                               + "," + str(flowRateArray[i]) + "," + str(numberOfFlows[i]) + "," + str(icmpRatioArray[i]) 
                               + "," + str(icmpPacketsArray[i])+ "," + str(packetSizeArray[i]) + "," + str(packetSizeRateArray[i])
                               + "," + str(packetNumberArray[i]) + "," + str(bytesArray[i]))
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
'''    
metricCalculation("/home/linneafg/silk-data/RawDataFromFilter/one-day-2011-01-10_11-sorted.rw", "2011-01-10 00:00:00", "2011-01-11 00:00:00",timedelta(minutes = 1), timedelta(minutes = 5))'''
