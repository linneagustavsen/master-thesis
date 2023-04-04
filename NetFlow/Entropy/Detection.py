from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime,timedelta
import numpy as np

'''
    Calculates entropy and other metrics and alerts in case of an anomaly
    Input:  silkFile:                       string, File with flow records sorted on time
            start:                          string, indicating the start time of the data wanted
            stop:                           string, indicating the stop time of the data wanted
            systemId:                       string, name of the system to collect and calculate on
            frequency:                      timedelta object, frequency of metric calculation
            interval:                       timedelta object, size of the sliding window which the calculation is made on
            windowSize:                     int, represents a multiplier of frequency, how far back we want to compare the value with
            thresholdSrcEntropy:            float, values over this threshold will cause an alert
            thresholdSrcEntropyRate:        float, values over this threshold will cause an alert
            thresholdDstEntropy:            float, values over this threshold will cause an alert
            thresholdDstEntropyRate:        float, values over this threshold will cause an alert
            thresholdFlowEntropy:           float, values over this threshold will cause an alert
            thresholdFlowEntropyRate:       float, values over this threshold will cause an alert
            thresholdNumberOfFlows:         int, values over this threshold will cause an alert
            thresholdICMPRatio:             float, values over this threshold will cause an alert
            thresholdNumberOfICMPPackets:   int, values over this threshold will cause an alert
            thresholdPSEntropy:             float, values over this threshold will cause an alert
            thresholdPSEntropyRate:         float, values over this threshold will cause an alert
            thresholdPackets:               int, values over this threshold will cause an alert
            thresholdBytes:                 float, values over this threshold will cause an alert
            attackDate:                     string, date of the attack the calculations are made on
'''
def detection(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdSrcEntropy, thresholdSrcEntropyRate, thresholdDstEntropy, thresholdDstEntropyRate, thresholdFlowEntropy, thresholdFlowEntropyRate, thresholdNumberOfFlows, thresholdICMPRatio, thresholdNumberOfICMPPackets, thresholdPSEntropy, thresholdPSEntropyRate, thresholdPackets, thresholdBytes, attackDate):
    #Open file to write alerts to
    srcEntropyFile = open("Detections/Entropy/NetFlow/SourceIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    srcEntropyRateFile = open("Detections/Entropy/NetFlow/SourceIPEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    dstEntropyFile = open("Detections/Entropy/NetFlow/DestinationIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    dstEntropyRateFile = open("Detections/Entropy/NetFlow/DestinationIPEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    flowEntropyFile = open("Detections/Entropy/NetFlow/FlowEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    flowEntropyRateFile = open("Detections/Entropy/NetFlow/FlowEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    flowFile = open("Detections/Threshold/NetFlow/NumberOfFlows."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    icmpRatioFile = open("Detections/Threshold/NetFlow/ICMPRatio."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    icmpPacketsFile = open("Detections/Threshold/NetFlow/ICMPPackets."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    packetSizeEntropyFile = open("Detections/Entropy/NetFlow/PacketSizeEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    packetSizeEntropyRateFile = open("Detections/Entropy/NetFlow/PacketSizeEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    packetsFile = open("Detections/Threshold/NetFlow/Packets."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    bytesFile = open("Detections/Threshold/NetFlow/Bytes."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    srcEntropyFile.write("Time,Change,Value,Mean of the last "+ str(windowSize))
    srcEntropyRateFile.write("Time,Change,Value,Mean of the last "+ str(windowSize))
    dstEntropyFile.write("Time,Change,Value,Mean of the last "+ str(windowSize))
    dstEntropyRateFile.write("Time,Change,Value,Mean of the last "+ str(windowSize))
    flowEntropyFile.write("Time,Change,Value,Mean of the last "+ str(windowSize))
    flowEntropyRateFile.write("Time,Change,Value,Mean of the last "+ str(windowSize))
    flowFile.write("Time,Change,Value,Mean of the last "+ str(windowSize))
    icmpRatioFile.write("Time,Change,Value,Mean of the last "+ str(windowSize))
    icmpPacketsFile.write("Time,Change,Value,Mean of the last "+ str(windowSize))
    packetSizeEntropyFile.write("Time,Change,Value,Mean of the last "+ str(windowSize))
    packetSizeEntropyRateFile.write("Time,Change,Value,Mean of the last "+ str(windowSize))
    packetsFile.write("Time,Change,Value,Mean of the last "+ str(windowSize))
    bytesFile.write("Time,Change,Value,Mean of the last "+ str(windowSize))

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
            
            #If there is enough stored values to compare with we compare the difference of each metric with a threshold
            if i >=windowSize:
                if abs(ipSrcArray[i] - np.nanmean(ipSrcArray[i-windowSize: i-1])) > thresholdSrcEntropy:
                    srcEntropyFile.write("\n" + str(startTime) + "," + str(abs(ipSrcArray[i] - np.nanmean(ipSrcArray[i-windowSize: i-1]))) + "," + str(ipSrcArray[i]) + "," + str(np.nanmean(ipSrcArray[i-windowSize: i-1])))
                
                if abs(ipSrcRateArray[i] - np.nanmean(ipSrcRateArray[i-windowSize: i-1])) > thresholdSrcEntropyRate:
                    srcEntropyRateFile.write("\n" + str(startTime) + "," + str(abs(ipSrcRateArray[i] - np.nanmean(ipSrcRateArray[i-windowSize: i-1]))) + "," + str(ipSrcRateArray[i]) + "," + str(np.nanmean(ipSrcRateArray[i-windowSize: i-1])))
                
                if abs(ipDstArray[i] - np.nanmean(ipDstArray[i-windowSize: i-1])) > thresholdDstEntropy:
                    dstEntropyFile.write("\n" + str(startTime) + "," + str(abs(ipDstArray[i] - np.nanmean(ipDstArray[i-windowSize: i-1]))) + "," + str(ipDstArray[i]) + "," + str(np.nanmean(ipDstArray[i-windowSize: i-1])))

                if abs(ipDstRateArray[i] - np.nanmean(ipDstRateArray[i-windowSize: i-1])) >  thresholdDstEntropyRate:
                    dstEntropyRateFile.write("\n" + str(startTime) + "," + str(abs(ipDstRateArray[i] - np.nanmean(ipDstRateArray[i-windowSize: i-1]))) + "," + str(ipDstRateArray[i]) + "," + str(np.nanmean(ipDstRateArray[i-windowSize: i-1])))

                if abs(flowArray[i] - np.nanmean(flowArray[i-windowSize: i-1])) > thresholdFlowEntropy:
                    flowEntropyFile.write("\n" + str(startTime) + "," + str(abs(flowArray[i] - np.nanmean(flowArray[i-windowSize: i-1]))) + "," + str(flowArray[i]) + "," + str(np.nanmean(flowArray[i-windowSize: i-1])))
                
                if abs(flowRateArray[i] - np.nanmean(flowRateArray[i-windowSize: i-1])) > thresholdFlowEntropyRate:
                    flowEntropyRateFile.write("\n" + str(startTime) + "," + str(abs(flowRateArray[i] - np.nanmean(flowRateArray[i-windowSize: i-1]))) + "," + str(flowRateArray[i]) + "," + str(np.nanmean(flowRateArray[i-windowSize: i-1])))
                
                if abs(numberOfFlows[i] - np.nanmean(numberOfFlows[i-windowSize: i-1])) > thresholdNumberOfFlows:
                    flowFile.write("\n" + str(startTime) + "," + str(abs(numberOfFlows[i] - np.nanmean(numberOfFlows[i-windowSize: i-1]))) + "," + str(numberOfFlows[i]) + "," + str(np.nanmean(numberOfFlows[i-windowSize: i-1])))
                 
                if abs(icmpRatioArray[i] - np.nanmean(icmpRatioArray[i-windowSize: i-1])) > thresholdICMPRatio:
                    icmpRatioFile.write("\n" + str(startTime) + "," + str(abs(icmpRatioArray[i] - np.nanmean(icmpRatioArray[i-windowSize: i-1]))) + "," + str(icmpRatioArray[i]) + "," + str(np.nanmean(icmpRatioArray[i-windowSize: i-1])))
                
                if abs(icmpPackets[i] - np.nanmean(icmpPackets[i-windowSize: i-1])) > thresholdNumberOfICMPPackets:
                    icmpPacketsFile.write("\n" + str(startTime) + "," + str(abs(icmpPackets[i] - np.nanmean(icmpPackets[i-windowSize: i-1]))) + "," + str(icmpPackets[i]) + "," + str(np.nanmean(icmpPackets[i-windowSize: i-1])))
                
                if abs(packetSizeArray[i] - np.nanmean(packetSizeArray[i-windowSize: i-1])) > thresholdPSEntropy:
                    packetSizeEntropyFile.write("\n" + str(startTime) + "," + str(abs(packetSizeArray[i] - np.nanmean(packetSizeArray[i-windowSize: i-1]))) + "," + str(packetSizeArray[i]) + "," + str(np.nanmean(packetSizeArray[i-windowSize: i-1])))
                
                if abs(packetSizeRateArray[i] - np.nanmean(packetSizeRateArray[i-windowSize: i-1])) > thresholdPSEntropyRate:
                    packetSizeEntropyRateFile.write("\n" + str(startTime) + "," + str(abs(packetSizeRateArray[i] - np.nanmean(packetSizeRateArray[i-windowSize: i-1]))) + "," + str(packetSizeRateArray[i]) + "," + str(np.nanmean(packetSizeRateArray[i-windowSize: i-1])))
                 
                if abs(packetNumberArray[i] - np.nanmean(packetNumberArray[i-windowSize: i-1])) > thresholdPackets:
                    packetsFile.write("\n" + str(startTime) + "," + str(abs(packetNumberArray[i] - np.nanmean(packetNumberArray[i-windowSize: i-1]))) + "," + str(packetNumberArray[i]) + "," + str(np.nanmean(packetNumberArray[i-windowSize: i-1])))
                
                if abs(bytesArray[i] - np.nanmean(bytesArray[i-windowSize: i-1])) > thresholdBytes:
                    bytesFile.write("\n" + str(startTime) + "," + str(abs(bytesArray[i] - np.nanmean(bytesArray[i-windowSize: i-1]))) + "," + str(bytesArray[i]) + "," + str(np.nanmean(bytesArray[i-windowSize: i-1])))
    
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
    