
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
def findBestRocScore(silkFile, start, stop, systemId, frequency, interval, windowSizes, alphas, attackDate):
    #Open files to write alerts to
    p = Path('Calculations')
    q = p / 'Entropy' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    #Open file to write alerts to


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
    labels = []

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

            numberOfPacketsPerSIP ={}
            numberOfPacketsPerDIP ={}
            numberOfPacketsPerFlow = {}
            flows = {}
            numberOfPacketsOfSizei = {}
            #A variable to keep track of the total amount of packets in this time interval
            sumOfPackets = 0
            icmpPackets = 0
            #Loop through each flow record in the time interval
            for rec in records:
                sumOfPackets += rec.packets
                #If the current flow has the same source IP as a previous flow the number of packets is added to the record of that source IP
                #If it has not been encountered before it is added to the dictionary
                if rec.sip in numberOfPacketsPerSIP:
                    numberOfPacketsPerSIP[rec.sip] += rec.packets
                else:
                    numberOfPacketsPerSIP[rec.sip] = rec.packets
                
                if rec.dip in numberOfPacketsPerDIP:
                    numberOfPacketsPerDIP[rec.dip] += rec.packets
                else:
                    numberOfPacketsPerDIP[rec.dip] = rec.packets
                
                flow = (rec.sip, rec.dip)
                reverse_flow = (rec.dip, rec.sip)

                #Find the index of the current flow in the dictionary if it exists
                #If not add it to the dictionary 
                if flow in flows:
                    index = flows[flow]
                elif reverse_flow in flows:
                    index = flows[reverse_flow]
                    flow = reverse_flow
                else:
                    index = len(flows)
                    flows[flow] = index
                    numberOfPacketsPerFlow[index] = 0
                #Add the packets of the current flow to the corresponding index in the other dictionary
                numberOfPacketsPerFlow[index] += rec.packets

                #Check if the flow is of the ICMP protocol
                #If it is we count up the packets in the flow
                if rec.protocol == 1 or rec.protocol == 58:
                    icmpPackets += rec.packets

                #If there are no packets the size is 0
                if rec.packets == 0:
                    size = 0
                else:
                    #If there are packets the average size of a packet is calculated for this measurement, cast to an integer, and stored
                    size = int(rec.bytes/rec.packets)
                #If the size of the packet has been encountered before the number of packets with this size is increased by the number of packets
                if size in numberOfPacketsOfSizei:
                    numberOfPacketsOfSizei[size] += rec.packets
                else:
                    numberOfPacketsOfSizei[size] = rec.packets
            
            #Array to keep track of the probability distribution
            PiSIP = []

            #Loop through each IP flow in the time interval
            for key, value in numberOfPacketsPerSIP.items():
                #Add the probability of the current source flow having the size that it does to the distribution
                PiSIP.append(value/sumOfPackets)
            ns = len(numberOfPacketsPerSIP)

            PiDIP = []
            
            #Loop through each IP flow in the time interval
            for key, value in numberOfPacketsPerDIP.items():
                #Add the probability of the current source flow having the size that it does to the distribution
                PiDIP.append(value/sumOfPackets)
            nd = len(numberOfPacketsPerDIP)
            
            PiF = []

            #Loop through each flow in the time interval
            for key, value in numberOfPacketsPerFlow.items():
                #Add the probability of flow having the size that it does to the distribution
                PiF.append(value/sumOfPackets)
            nf = len(flows)

            #Find the ratio of ICMP packets in this time interval
            icmpRatio = icmpPackets/sumOfPackets

            PiPS = []

            sumOfNP = sum(numberOfPacketsOfSizei.values())

            #Loop through all of the packet sizes
            for key, value in numberOfPacketsOfSizei.items():
                #Add the probability of the current packet size being the size that it does to the distribution
                PiPS.append(value/sumOfNP)
            nps = len(numberOfPacketsOfSizei)

            currentIpSrcArray = []
            currentIpSrcRateArray = []
            currentIpDstArray = []
            currentIpDstRateArray = []
            currentFlowArray = []
            currentFlowRateArray = []
            currentPacketSizeArray = []
            currentPacketSizeRateArray = []
            for alpha in alphas:
                #Calculate the generalized entropy of this distribution
                entropyPacketSize = generalizedEntropy(alpha, PiPS)

                #Calculate the generalized entropy of this distribution
                entropyDip = generalizedEntropy(alpha,PiDIP)

                #Calculate the generalized entropy of this distribution
                entropySip = generalizedEntropy(alpha,PiSIP)

                #Calculate the generalized entropy of this distribution
                entropyFlow = generalizedEntropy(alpha, PiF)

                currentIpSrcArray.append(entropySip)
                currentIpSrcRateArray.append(entropySip/ns)
                currentIpDstArray.append(entropyDip)
                currentIpDstRateArray.append(entropyDip/nd)
                currentFlowArray.append(entropyFlow)
                currentFlowRateArray.append(entropyFlow/nf)
                currentPacketSizeArray.append(entropyPacketSize)
                currentPacketSizeRateArray.append(entropyPacketSize/nps)

            ipSrcArray.append(currentIpSrcArray)
            ipSrcRateArray.append(currentIpSrcRateArray)
            ipDstArray.append(currentIpDstArray)
            ipDstRateArray.append(currentIpDstRateArray)
            flowArray.append(currentFlowArray)
            flowRateArray.append(currentFlowRateArray)
            packetSizeArray.append(currentPacketSizeArray)
            packetSizeRateArray.append(currentPacketSizeRateArray)

            numberOfFlows.append(nf)
            icmpRatioArray.append(icmpRatio)
            icmpPacketsArray.append(icmpPackets)
            
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
            labels.append(label)
            
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1
        #Check if it is an attack flow
        if isAttackFlow(rec.sip, rec.dip, rec.stime, rec.etime):
            attackFlowArray.append(rec.stime)
        records.append(rec)
    infile.close()

    ipSrcArray = np.array(ipSrcArray)
    ipSrcRateArray = np.array(ipSrcRateArray)
    ipDstArray = np.array(ipDstArray)
    ipDstRateArray = np.array(ipDstRateArray)
    flowArray = np.array(flowArray)
    flowRateArray = np.array(flowRateArray)
    packetSizeArray = np.array(packetSizeArray)
    packetSizeRateArray = np.array(packetSizeRateArray)
    for windowSize in windowSizes:
        for a in range(len(alphas)):
            alpha = alphas[a]
            calculations = open(str(q) + "/alpha."+ str(alpha)+ ".windowSize."+ str(windowSize)+ "."+ str(int(frequency.total_seconds()))+ "secFrequency." +str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
            
            #Write the column titles to the files
            calculations.write("dstEntropy,dstEntropyRate,srcEntropy,srcEntropyRate,flowEntropy,flowEntropyRate,numberOfFlows,icmpRatio,icmpPackets,packetSizeEntropy,packetSizeEntropyRate,numberOfPackets,numberOfBytes,real_label")
            for i in range(len(labels)):
                if i >=windowSize:
                    calculations.write("\n" + str(abs(ipSrcArray[i,a] - np.nanmean(ipSrcArray[i-windowSize: i-1,a]))) + "," + str(abs(ipSrcRateArray[i,a] - np.nanmean(ipSrcRateArray[i-windowSize: i-1,a]))) 
                                + "," + str(abs(ipDstArray[i,a] - np.nanmean(ipDstArray[i-windowSize: i-1,a]))) + "," + str(abs(ipDstRateArray[i,a] - np.nanmean(ipDstRateArray[i-windowSize: i-1,a]))) + "," + str(abs(flowArray[i,a] - np.nanmean(flowArray[i-windowSize: i-1,a]))) 
                                + "," + str(abs(flowRateArray[i,a] - np.nanmean(flowRateArray[i-windowSize: i-1,a]))) + "," + str(abs(numberOfFlows[i] - np.nanmean(numberOfFlows[i-windowSize: i-1]))) + "," + str(abs(icmpRatioArray[i] - np.nanmean(icmpRatioArray[i-windowSize: i-1]))) 
                                + "," + str(abs(icmpPacketsArray[i] - np.nanmean(icmpPacketsArray[i-windowSize: i-1])))+ "," + str(abs(packetSizeArray[i,a] - np.nanmean(packetSizeArray[i-windowSize: i-1,a]))) + "," + str(abs(packetSizeRateArray[i,a] - np.nanmean(packetSizeRateArray[i-windowSize: i-1,a])))
                                + "," + str(abs(packetNumberArray[i] - np.nanmean(packetNumberArray[i-windowSize: i-1]))) + "," + str(abs(bytesArray[i] - np.nanmean(bytesArray[i-windowSize: i-1]))) + "," + str(labels[i]))

                else:
                    calculations.write("\n" +  str(None) + "," + str(None) + ","+str(None) + ","+str(None) + ","+str(None) + ","+str(None) + ","+str(None) + ","+str(None) + "," + str(None) + ","+str(None) + ","+str(None) + ","+str(None) + ","+str(None) + ","+ str(labels[i]))
                    
               

        calculations.close()