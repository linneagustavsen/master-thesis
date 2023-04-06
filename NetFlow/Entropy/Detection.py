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
    srcEntropyFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    srcEntropyRateFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    dstEntropyFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    dstEntropyRateFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    flowEntropyFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    flowEntropyRateFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    flowFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    icmpRatioFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    icmpPacketsFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    packetSizeEntropyFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    packetSizeEntropyRateFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    packetsFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    bytesFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))

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

    #Loop through all the flow records in the input file
    for rec in infile:
        if rec.etime >= stopTime:
            break
        if rec.stime < startTime:
            continue
        if rec.stime > windowTime + frequency:
            lastSizes = 0
            for size in sizes:
                lastSizes += size
            thisMinuteSize = len(records) - lastSizes
            sizes.append(thisMinuteSize)
            windowTime += frequency
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
                    srcEntropyFile.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(ipSrcArray[i] - np.nanmean(ipSrcArray[i-windowSize: i-1]))) + "," + str(ipSrcArray[i]) + "," + str(np.nanmean(ipSrcArray[i-windowSize: i-1])))
                
                if abs(ipSrcRateArray[i] - np.nanmean(ipSrcRateArray[i-windowSize: i-1])) > thresholdSrcEntropyRate:
                    srcEntropyRateFile.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(ipSrcRateArray[i] - np.nanmean(ipSrcRateArray[i-windowSize: i-1]))) + "," + str(ipSrcRateArray[i]) + "," + str(np.nanmean(ipSrcRateArray[i-windowSize: i-1])))
                
                if abs(ipDstArray[i] - np.nanmean(ipDstArray[i-windowSize: i-1])) > thresholdDstEntropy:
                    dstEntropyFile.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(ipDstArray[i] - np.nanmean(ipDstArray[i-windowSize: i-1]))) + "," + str(ipDstArray[i]) + "," + str(np.nanmean(ipDstArray[i-windowSize: i-1])))

                if abs(ipDstRateArray[i] - np.nanmean(ipDstRateArray[i-windowSize: i-1])) >  thresholdDstEntropyRate:
                    dstEntropyRateFile.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(ipDstRateArray[i] - np.nanmean(ipDstRateArray[i-windowSize: i-1]))) + "," + str(ipDstRateArray[i]) + "," + str(np.nanmean(ipDstRateArray[i-windowSize: i-1])))

                if abs(flowArray[i] - np.nanmean(flowArray[i-windowSize: i-1])) > thresholdFlowEntropy:
                    flowEntropyFile.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(flowArray[i] - np.nanmean(flowArray[i-windowSize: i-1]))) + "," + str(flowArray[i]) + "," + str(np.nanmean(flowArray[i-windowSize: i-1])))
                
                if abs(flowRateArray[i] - np.nanmean(flowRateArray[i-windowSize: i-1])) > thresholdFlowEntropyRate:
                    flowEntropyRateFile.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(flowRateArray[i] - np.nanmean(flowRateArray[i-windowSize: i-1]))) + "," + str(flowRateArray[i]) + "," + str(np.nanmean(flowRateArray[i-windowSize: i-1])))
                
                if abs(numberOfFlows[i] - np.nanmean(numberOfFlows[i-windowSize: i-1])) > thresholdNumberOfFlows:
                    flowFile.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(numberOfFlows[i] - np.nanmean(numberOfFlows[i-windowSize: i-1]))) + "," + str(numberOfFlows[i]) + "," + str(np.nanmean(numberOfFlows[i-windowSize: i-1])))
                 
                if abs(icmpRatioArray[i] - np.nanmean(icmpRatioArray[i-windowSize: i-1])) > thresholdICMPRatio:
                    icmpRatioFile.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(icmpRatioArray[i] - np.nanmean(icmpRatioArray[i-windowSize: i-1]))) + "," + str(icmpRatioArray[i]) + "," + str(np.nanmean(icmpRatioArray[i-windowSize: i-1])))
                
                if abs(icmpPacketsArray[i] - np.nanmean(icmpPacketsArray[i-windowSize: i-1])) > thresholdNumberOfICMPPackets:
                    icmpPacketsFile.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(icmpPacketsArray[i] - np.nanmean(icmpPacketsArray[i-windowSize: i-1]))) + "," + str(icmpPacketsArray[i]) + "," + str(np.nanmean(icmpPacketsArray[i-windowSize: i-1])))
                
                if abs(packetSizeArray[i] - np.nanmean(packetSizeArray[i-windowSize: i-1])) > thresholdPSEntropy:
                    packetSizeEntropyFile.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(packetSizeArray[i] - np.nanmean(packetSizeArray[i-windowSize: i-1]))) + "," + str(packetSizeArray[i]) + "," + str(np.nanmean(packetSizeArray[i-windowSize: i-1])))
                
                if abs(packetSizeRateArray[i] - np.nanmean(packetSizeRateArray[i-windowSize: i-1])) > thresholdPSEntropyRate:
                    packetSizeEntropyRateFile.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(packetSizeRateArray[i] - np.nanmean(packetSizeRateArray[i-windowSize: i-1]))) + "," + str(packetSizeRateArray[i]) + "," + str(np.nanmean(packetSizeRateArray[i-windowSize: i-1])))
                 
                if abs(packetNumberArray[i] - np.nanmean(packetNumberArray[i-windowSize: i-1])) > thresholdPackets:
                    packetsFile.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(packetNumberArray[i] - np.nanmean(packetNumberArray[i-windowSize: i-1]))) + "," + str(packetNumberArray[i]) + "," + str(np.nanmean(packetNumberArray[i-windowSize: i-1])))
                
                if abs(bytesArray[i] - np.nanmean(bytesArray[i-windowSize: i-1])) > thresholdBytes:
                    bytesFile.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(bytesArray[i] - np.nanmean(bytesArray[i-windowSize: i-1]))) + "," + str(bytesArray[i]) + "," + str(np.nanmean(bytesArray[i-windowSize: i-1])))
    
                '''
                CHAT GPT VERSION
                arrays = [ipSrcArray, ipSrcRateArray, ipDstArray, ipDstRateArray, flowArray, flowRateArray, numberOfFlows, icmpRatioArray, icmpPackets, packetSizeArray, packetSizeRateArray]
                thresholds = [thresholdSrcEntropy, thresholdSrcEntropyRate, thresholdDstEntropy, thresholdDstEntropyRate, thresholdFlowEntropy, thresholdFlowEntropyRate, thresholdNumberOfFlows, thresholdICMPRatio, thresholdNumberOfICMPPackets, thresholdPSEntropy, thresholdPSEntropyRate]
                files = [srcEntropyFile, srcEntropyRateFile, dstEntropyFile, dstEntropyRateFile, flowEntropyFile, flowEntropyRateFile, flowFile, icmpRatioFile, icmpPacketsFile, packetSizeEntropyFile, packetSizeEntropyRateFile]

                for i in range(len(arrays)):
                    array = arrays[i]
                    threshold = thresholds[i]
                    file = files[i]

                    if abs(array[i] - np.nanmean(array[i-windowSize: i-1])) > threshold:
                        file.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(array[i] - np.nanmean(array[i-windowSize: i-1]))) + "," + str(array[i]) + "," + str(np.nanmean(array[i-windowSize: i-1])))
                '''
            #Reset the record aggregation
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1
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
    