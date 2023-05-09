import pickle
import pandas as pd
from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime
from HelperFunctions.IsAttack import *
from pathlib import Path

'''
    Calculates entropy and other metrics and write them to file. Also checks if the flow is an attack flow
    Input:  
            silkFile:   string, file with flow records sorted on time
            start:      string, indicating the start time of the data wanted
            stop:       string, indicating the stop time of the data wanted
            systemId:   string, name of the system to collect and calculate on
            frequency:  timedelta object, frequency of metric calculation
            interval:   timedelta object, size of the sliding window which the calculation is made on
            attackDate: string, date of the attack the calculations are made on
'''
def metricCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate):
    #Open files to write alerts to
    p = Path('Calculations')
    q = p / 'Entropy' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    calculations = open(str(q) + "/Metrics."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    attackFlows = open(str(q) + "/AttackFlows."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    srcDistributionDict ={}
    dstDistributionDict ={}
    packetSizeDistributionDict ={}

    #Write the column titles to the files
    calculations.write("sTime,eTime,srcEntropy,srcEntropyRate,dstEntropy,dstEntropyRate,flowEntropy,flowEntropyRate,numberOfFlows,icmpRatio,icmpPackets,packetSizeEntropy,packetSizeEntropyRate,numberOfPackets,numberOfBytes")
    attackFlows.write("sTime,eTime")

    #Makes datetime objects of the input times
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    windowTime = startTime
    starting = startTime
    pushed = False

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
    #Instantiate variables
    i = 0
    sizes = []
    attackFlowArray = []

    #Loop through all the flow records in the input file
    for rec in infile:
        if rec.etime > stopTime + frequency:
            continue
        if rec.stime < startTime:
            continue
        if rec.stime >= starting and not pushed:
            startTime = rec.stime.replace(microsecond = 0, second = 0)
            pushed = True
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
            #Find the probability distribution based on how many packets there is in each source flow in this time interval
            PiSIP, ns = ipSourceDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropySip = generalizedEntropy(10,PiSIP)
            ipSrcArray.append(entropySip)
            #Calculate the generalized entropy rate of this distribution
            ipSrcRateArray.append(entropySip/ns)
            srcDistributionDict[rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ")] = PiSIP

            #Find the probability distribution based on how many packets there is in each destination flow in this time interval
            PiDIP, nd = ipDestinationDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropyDip = generalizedEntropy(10,PiDIP)
            ipDstArray.append(entropyDip)
            #Calculate the generalized entropy rate of this distribution
            ipDstRateArray.append(entropyDip/nd)
            dstDistributionDict[rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ")] = PiDIP
            
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
            PiPS,nps = packetSizeDistributionNetFlow(records)
            #Calculate the generalized entropy of this distribution
            entropyPacketSize = generalizedEntropy(10, PiPS)
            packetSizeArray.append(entropyPacketSize)
            #Calculate the generalized entropy rate of this distribution
            packetSizeRateArray.append(entropyPacketSize/nps)
            packetSizeDistributionDict[rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ")] = PiPS

            #Store the number of packets and bytes this time interval
            packetNumberArray.append(numberOfPackets(records))
            bytesArray.append(numberOfBytes(records))

            if i == 0:
                timeInterval = pd.Interval(pd.Timestamp(startTime), pd.Timestamp(rec.stime.replace(microsecond = 0, second = 0)), closed="both")
            else:
                timeInterval = pd.Interval(pd.Timestamp(rec.stime.replace(microsecond = 0, second = 0) - frequency), pd.Timestamp(rec.stime.replace(microsecond = 0, second = 0)), closed="right")
            label = 0
            for timestamp in attackFlowArray:
                if timestamp in timeInterval:
                    label = 1

            calculations.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(ipSrcArray[i]) + "," + str(ipSrcRateArray[i]) 
                               + "," + str(ipDstArray[i]) + "," + str(ipDstRateArray[i]) + "," + str(flowArray[i]) 
                               + "," + str(flowRateArray[i]) + "," + str(numberOfFlows[i]) + "," + str(icmpRatioArray[i]) 
                               + "," + str(icmpPacketsArray[i])+ "," + str(packetSizeArray[i]) + "," + str(packetSizeRateArray[i])
                               + "," + str(packetNumberArray[i]) + "," + str(bytesArray[i]) + "," + str(label))
            #Push the sliding window
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1
        #Check if it is an attack flow
        if isAttackFlow(rec.sip, rec.dip, rec.stime, rec.etime):
            attackFlows.write("\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + ","+ rec.etime.strftime("%Y-%m-%dT%H:%M:%SZ"))
            attackFlowArray.append(rec.stime)
        records.append(rec)
    
    calculations.close()
    attackFlows.close()

    infile.close()

    json_file = open(str(q) + "/srcIPDistributions."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl", "w")
    pickle.dump(srcDistributionDict,json_file)
    json_file.close()

    json_file = open(str(q) + "/dstIPDistributions."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl", "w")
    pickle.dump(dstDistributionDict,json_file)
    json_file.close()

    json_file = open(str(q) + "/packetSizeDistributions."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl", "w")
    pickle.dump(packetSizeDistributionDict,json_file)
    json_file.close()
'''    
metricCalculation("/home/linneafg/silk-data/RawDataFromFilter/one-day-2011-01-10_11-sorted.rw", "2011-01-10 00:00:00", "2011-01-11 00:00:00",timedelta(minutes = 1), timedelta(minutes = 5))'''
