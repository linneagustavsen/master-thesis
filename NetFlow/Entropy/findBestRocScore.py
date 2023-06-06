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
def findBestRocScore(silkFile, start, stop, systemId, frequency, interval, windowSize, attackDate):
    #Open files to write alerts to
    p = Path('Calculations')
    q = p / 'Entropy' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    #Open file to write alerts to
    srcEntropyFile = open(str(q) + "/SourceIPEntropy.windowSize."+ str(windowSize)+ "."+ str(int(frequency.total_seconds()))+ "secFrequency." +str(int(frequency.total_seconds()))+ "secFrequency." +str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    srcEntropyRateFile = open(str(q) + "/SourceIPEntropyRatewindowSize."+ str(windowSize)+ "."+ str(int(frequency.total_seconds()))+ "secFrequency." +str(int(frequency.total_seconds()))+ "secFrequency." +str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    dstEntropyFile = open(str(q) + "/DestinationIPEntropywindowSize."+ str(windowSize)+ "."+ str(int(frequency.total_seconds()))+ "secFrequency." +str(int(frequency.total_seconds()))+ "secFrequency." +str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    dstEntropyRateFile = open(str(q) + "/DestinationIPEntropyRatewindowSize."+ str(windowSize)+ "."+ str(int(frequency.total_seconds()))+ "secFrequency." +str(int(frequency.total_seconds()))+ "secFrequency." +str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    flowEntropyFile = open(str(q) + "/FlowEntropywindowSize."+ str(windowSize)+ "."+ str(int(frequency.total_seconds()))+ "secFrequency." +str(int(frequency.total_seconds()))+ "secFrequency." +str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    flowEntropyRateFile = open(str(q) + "/FlowEntropyRatewindowSize."+ str(windowSize)+ "."+ str(int(frequency.total_seconds()))+ "secFrequency." +str(int(frequency.total_seconds()))+ "secFrequency." +str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    flowFile = open(str(q) + "/NumberOfFlowswindowSize."+ str(windowSize)+ "."+ str(int(frequency.total_seconds()))+ "secFrequency." +str(int(frequency.total_seconds()))+ "secFrequency." +str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    icmpRatioFile = open(str(q) + "/ICMPRatiowindowSize."+ str(windowSize)+ "."+ str(int(frequency.total_seconds()))+ "secFrequency." +str(int(frequency.total_seconds()))+ "secFrequency." +str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    icmpPacketsFile = open(str(q) + "/ICMPPacketswindowSize."+ str(windowSize)+ "."+ str(int(frequency.total_seconds()))+ "secFrequency." +str(int(frequency.total_seconds()))+ "secFrequency." +str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    packetSizeEntropyFile = open(str(q) + "/PacketSizeEntropywindowSize."+ str(windowSize)+ "."+ str(int(frequency.total_seconds()))+ "secFrequency." +str(int(frequency.total_seconds()))+ "secFrequency." +str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    packetSizeEntropyRateFile = open(str(q) + "/PacketSizeEntropyRatewindowSize."+ str(windowSize)+ "."+ str(int(frequency.total_seconds()))+ "secFrequency." +str(int(frequency.total_seconds()))+ "secFrequency." +str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    packetsFile = open(str(q) + "/PacketswindowSize."+ str(windowSize)+ "."+ str(int(frequency.total_seconds()))+ "secFrequency." +str(int(frequency.total_seconds()))+ "secFrequency." +str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    bytesFile = open(str(q) + "/ByteswindowSize."+ str(windowSize)+ "."+ str(int(frequency.total_seconds()))+ "secFrequency." +str(int(frequency.total_seconds()))+ "secFrequency." +str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    srcEntropyFile.write("sTime,eTime,Change,Value,Mean_last_"+ str(windowSize)+",real_label")
    srcEntropyRateFile.write("sTime,eTime,Change,Value,Mean_last_"+ str(windowSize)+",real_label")
    dstEntropyFile.write("sTime,eTime,Change,Value,Mean_last_"+ str(windowSize)+",real_label")
    dstEntropyRateFile.write("sTime,eTime,Change,Value,Mean_last_"+ str(windowSize)+",real_label")
    flowEntropyFile.write("sTime,eTime,Change,Value,Mean_last_"+ str(windowSize)+",real_label")
    flowEntropyRateFile.write("sTime,eTime,Change,Value,Mean_last_"+ str(windowSize)+",real_label")
    flowFile.write("sTime,eTime,Change,Value,Mean_last_"+ str(windowSize)+",real_label")
    icmpRatioFile.write("sTime,eTime,Change,Value,Mean_last_"+ str(windowSize)+",real_label")
    icmpPacketsFile.write("sTime,eTime,Change,Value,Mean_last_"+ str(windowSize)+",real_label")
    packetSizeEntropyFile.write("sTime,eTime,Change,Value,Mean_last_"+ str(windowSize)+",real_label")
    packetSizeEntropyRateFile.write("sTime,eTime,Change,Value,Mean_last_"+ str(windowSize)+",real_label")
    packetsFile.write("sTime,eTime,Change,Value,Mean_last_"+ str(windowSize)+",real_label")
    bytesFile.write("sTime,eTime,Change,Value,Mean_last_"+ str(windowSize)+",real_label")


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

            #Calculate the generalized entropy of this distribution
            entropySip = generalizedEntropy(10,PiSIP)

            PiDIP = []
            
            #Loop through each IP flow in the time interval
            for key, value in numberOfPacketsPerDIP.items():
                #Add the probability of the current source flow having the size that it does to the distribution
                PiDIP.append(value/sumOfPackets)
            nd = len(numberOfPacketsPerDIP)

            #Calculate the generalized entropy of this distribution
            entropyDip = generalizedEntropy(10,PiDIP)
            
            PiF = []

            #Loop through each flow in the time interval
            for key, value in numberOfPacketsPerFlow.items():
                #Add the probability of flow having the size that it does to the distribution
                PiF.append(value/sumOfPackets)
            nf = len(flows)
            #Calculate the generalized entropy of this distribution
            entropyFlow = generalizedEntropy(10, PiF)

            #Find the ratio of ICMP packets in this time interval
            icmpRatio = icmpPackets/sumOfPackets

            PiPS = []

            sumOfNP = sum(numberOfPacketsOfSizei.values())

            #Loop through all of the packet sizes
            for key, value in numberOfPacketsOfSizei.items():
                #Add the probability of the current packet size being the size that it does to the distribution
                PiPS.append(value/sumOfNP)
            nps = len(numberOfPacketsOfSizei)

            #Calculate the generalized entropy of this distribution
            entropyPacketSize = generalizedEntropy(10, PiPS)


            ipSrcArray.append(entropySip)
            ipSrcRateArray.append(entropySip/ns)
            ipDstArray.append(entropyDip)
            ipDstRateArray.append(entropyDip/nd)
            flowArray.append(entropyFlow)
            flowRateArray.append(entropyFlow/nf)
            numberOfFlows.append(nf)
            icmpRatioArray.append(icmpRatio)
            icmpPacketsArray.append(icmpPackets)
            packetSizeArray.append(entropyPacketSize)
            packetSizeRateArray.append(entropyPacketSize/nps)
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
            
            if i >=windowSize:
                srcEntropyFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(ipSrcArray[i] - np.nanmean(ipSrcArray[i-windowSize: i-1]))) + "," + str(ipSrcArray[i]) + "," + str(np.nanmean(ipSrcArray[i-windowSize: i-1])) + "," + str(label))
                
                srcEntropyRateFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(ipSrcRateArray[i] - np.nanmean(ipSrcRateArray[i-windowSize: i-1]))) + "," + str(ipSrcRateArray[i]) + "," + str(np.nanmean(ipSrcRateArray[i-windowSize: i-1])) + "," + str(label))
                
                dstEntropyFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(ipDstArray[i] - np.nanmean(ipDstArray[i-windowSize: i-1]))) + "," + str(ipDstArray[i]) + "," + str(np.nanmean(ipDstArray[i-windowSize: i-1])) + "," + str(label))

                dstEntropyRateFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(ipDstRateArray[i] - np.nanmean(ipDstRateArray[i-windowSize: i-1]))) + "," + str(ipDstRateArray[i]) + "," + str(np.nanmean(ipDstRateArray[i-windowSize: i-1])) + "," + str(label))

                flowEntropyFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(flowArray[i] - np.nanmean(flowArray[i-windowSize: i-1]))) + "," + str(flowArray[i]) + "," + str(np.nanmean(flowArray[i-windowSize: i-1])) + "," + str(label))
                
                flowEntropyRateFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(flowRateArray[i] - np.nanmean(flowRateArray[i-windowSize: i-1]))) + "," + str(flowRateArray[i]) + "," + str(np.nanmean(flowRateArray[i-windowSize: i-1])) + "," + str(label))
                
                flowFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(numberOfFlows[i] - np.nanmean(numberOfFlows[i-windowSize: i-1]))) + "," + str(numberOfFlows[i]) + "," + str(np.nanmean(numberOfFlows[i-windowSize: i-1]))+ "," + str(label))
                 
                icmpRatioFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(icmpRatioArray[i] - np.nanmean(icmpRatioArray[i-windowSize: i-1]))) + "," + str(icmpRatioArray[i]) + "," + str(np.nanmean(icmpRatioArray[i-windowSize: i-1])) + "," + str(label))
                
                icmpPacketsFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(icmpPacketsArray[i] - np.nanmean(icmpPacketsArray[i-windowSize: i-1]))) + "," + str(icmpPacketsArray[i]) + "," + str(np.nanmean(icmpPacketsArray[i-windowSize: i-1])) + "," + str(label))
                
                packetSizeEntropyFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(packetSizeArray[i] - np.nanmean(packetSizeArray[i-windowSize: i-1]))) + "," + str(packetSizeArray[i]) + "," + str(np.nanmean(packetSizeArray[i-windowSize: i-1])) + "," + str(label))
                
                packetSizeEntropyRateFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(packetSizeRateArray[i] - np.nanmean(packetSizeRateArray[i-windowSize: i-1]))) + "," + str(packetSizeRateArray[i]) + "," + str(np.nanmean(packetSizeRateArray[i-windowSize: i-1])) + "," + str(label))
                 
                packetsFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(packetNumberArray[i] - np.nanmean(packetNumberArray[i-windowSize: i-1]))) + "," + str(packetNumberArray[i]) + "," + str(np.nanmean(packetNumberArray[i-windowSize: i-1])) + "," + str(label))
                
                bytesFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(bytesArray[i] - np.nanmean(bytesArray[i-windowSize: i-1]))) + "," + str(bytesArray[i]) + "," + str(np.nanmean(bytesArray[i-windowSize: i-1])) + "," + str(label))
            
            
            else:
                srcEntropyFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(None) + "," + str(ipSrcArray[i]) + "," + str(None) + "," + str(label))
                
                srcEntropyRateFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(None) + "," + str(ipSrcRateArray[i]) + "," + str(None) + "," + str(label))
                
                dstEntropyFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(None) + "," + str(ipDstArray[i]) + "," + str(None) + "," + str(label))

                dstEntropyRateFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(None) + "," + str(ipDstRateArray[i]) + "," + str(None) + "," + str(label))

                flowEntropyFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(None) + "," + str(flowArray[i]) + "," + str(None) + "," + str(label))
                
                flowEntropyRateFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(None) + "," + str(flowRateArray[i]) + "," + str(None) + "," + str(label))
                
                flowFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(None) + "," + str(numberOfFlows[i]) + "," + str(None)+ "," + str(label))
                 
                icmpRatioFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(None) + "," + str(icmpRatioArray[i]) + "," + str(None) + "," + str(label))
                
                icmpPacketsFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(None) + "," + str(icmpPacketsArray[i]) + "," + str(None) + "," + str(label))
                
                packetSizeEntropyFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(None) + "," + str(packetSizeArray[i]) + "," + str(None) + "," + str(label))
                
                packetSizeEntropyRateFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(None) + "," + str(packetSizeRateArray[i]) + "," + str(None) + "," + str(label))
                 
                packetsFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(None) + "," + str(packetNumberArray[i]) + "," + str(None) + "," + str(label))
                
                bytesFile.write("\n" + timeInterval.left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeInterval.right.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(None) + "," + str(bytesArray[i]) + "," + str(None) + "," + str(label))

            
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1
        #Check if it is an attack flow
        if isAttackFlow(rec.sip, rec.dip, rec.stime, rec.etime):
            attackFlowArray.append(rec.stime)
        records.append(rec)
    srcEntropyFile.close()
    srcEntropyRateFile.close()
    dstEntropyFile.close()
    dstEntropyRateFile.close()
    flowEntropyFile.close()
    flowEntropyRateFile.close()
    flowFile.close()
    icmpRatioFile.close()
    icmpPacketsFile.close()
    packetSizeEntropyFile.close()
    packetSizeEntropyRateFile.close()
    packetsFile.close()
    bytesFile.close()

    infile.close()