import json
import pickle
import numpy as np
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
def findMinMaxMetricCalc(silkFile, start, stop, frequency, interval, windowSize):

    #Makes datetime objects of the input times
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    windowTime = startTime
    starting = startTime
    pushed = False

    #Instantiate empty arrays for the calculated values
    records = []
    
    changes_sip = []
    changes_sip_r = []
    min_sip = 100000000000000
    min_sip_r = 100000000000000
    ipSrcArray = []
    ipSrcRateArray = []

    changes_dip = []
    changes_dip_r = []
    min_dip = 100000000000000
    min_dip_r = 100000000000000
    ipDstArray = []
    ipDstRateArray = []

    changes_f = []
    changes_f_r = []
    min_f = 100000000000000
    min_f_r = 100000000000000
    flowArray = []
    flowRateArray = []

    changes_nf = []
    min_nf = 100000000000000
    numberOfFlows = []

    changes_ICMP_ratio = []
    changes_ICMP_packets = []
    icmpRatioArray = []
    icmpPacketsArray = []

    changes_PS = []
    changes_PS_r = []
    min_PS = 100000000000000
    min_PS_r = 100000000000000
    packetSizeArray = []
    packetSizeRateArray = []

    changes_packets = []
    changes_bytes = []
    min_packets = 100000000000000
    min_bytes = 100000000000000
    packetNumberArray = []
    bytesArray = []
    #Instantiate variables
    i = 0
    sizes = []
    for week in range(1,8):
        silkFile = "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw1/week"+ str(week)+ ".rw"
        
        # Open a silk flow file for reading
        infile = silkfile_open(silkFile, READ)
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
                #srcDistributionDict[rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ")] = PiSIP

                #Find the probability distribution based on how many packets there is in each destination flow in this time interval
                PiDIP, nd = ipDestinationDistribution(records)
                #Calculate the generalized entropy of this distribution
                entropyDip = generalizedEntropy(10,PiDIP)
                ipDstArray.append(entropyDip)
                #Calculate the generalized entropy rate of this distribution
                ipDstRateArray.append(entropyDip/nd)
                #dstDistributionDict[rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ")] = PiDIP
                
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

                #Store the number of packets and bytes this time interval
                packetNumberArray.append(numberOfPackets(records))
                bytesArray.append(numberOfBytes(records))

                change_sip = abs(ipSrcArray[i] - np.nanmean(ipSrcArray[i-windowSize: i-1]))
                if change_sip < min_sip:
                    min_sip = change_sip
                changes_sip.append(change_sip)
                
                change_sip_r = abs(ipSrcRateArray[i] - np.nanmean(ipSrcRateArray[i-windowSize: i-1]))
                if change_sip_r < min_sip_r:
                    min_sip_r = change_sip_r
                changes_sip_r.append(change_sip_r)
                
                change_dip = abs(ipDstArray[i] - np.nanmean(ipDstArray[i-windowSize: i-1]))
                if change_dip < min_dip:
                    min_dip = change_dip
                changes_dip.append(change_dip)

                change_dip_r = abs(ipDstRateArray[i] - np.nanmean(ipDstRateArray[i-windowSize: i-1]))
                if change_dip_r < min_dip_r:
                    min_dip_r = change_dip_r
                changes_dip_r.append(change_dip_r)

                change_f = abs(flowArray[i] - np.nanmean(flowArray[i-windowSize: i-1]))
                if change_f < min_f:
                    min_f = change_f
                changes_f.append(change_f)
                
                change_f_r = abs(flowRateArray[i] - np.nanmean(flowRateArray[i-windowSize: i-1]))
                if change_f_r < min_f_r:
                    min_f_r = change_f_r
                changes_f_r.append(change_f_r) 
                
                change_nf = abs(numberOfFlows[i] - np.nanmean(numberOfFlows[i-windowSize: i-1]))
                if change_nf < min_nf:
                    min_nf = change_nf
                changes_nf.append(change_nf)
                
                change_ICMP_ratio = abs(icmpRatioArray[i] - np.nanmean(icmpRatioArray[i-windowSize: i-1]))
                changes_ICMP_ratio.append(change_ICMP_ratio)

                change_ICMP_packets = abs(icmpPacketsArray[i] - np.nanmean(icmpPacketsArray[i-windowSize: i-1]))
                changes_ICMP_packets.append(change_ICMP_packets)
                if change_ICMP_ratio != 0:
                    print(change_ICMP_ratio)
                if change_ICMP_packets !=  0:
                    print(change_ICMP_packets)

                change_PS = abs(packetSizeArray[i] - np.nanmean(packetSizeArray[i-windowSize: i-1]))
                if change_PS < min_PS:
                    min_PS = change_PS
                changes_PS.append(change_PS)
                
                change_PS_r = abs(packetSizeRateArray[i] - np.nanmean(packetSizeRateArray[i-windowSize: i-1]))
                if change_PS_r < min_PS_r:
                    min_PS_r = change_PS_r
                changes_PS_r.append(change_PS_r)
                
                change_packets = abs(packetNumberArray[i] - np.nanmean(packetNumberArray[i-windowSize: i-1]))
                if change_packets < min_packets:
                    min_packets = change_packets
                changes_packets.append(change_packets)
                
                change_bytes = abs(bytesArray[i] - np.nanmean(bytesArray[i-windowSize: i-1]))
                if change_bytes < min_bytes:
                    min_bytes = change_bytes
                changes_bytes.append(change_bytes)
                #Push the sliding window
                startTime = startTime + frequency
                records = records[sizes[0]:]
                sizes.pop(0)
                i += 1
            records.append(rec)

        infile.close()

    json_file = open("NetFlow/Entropy/Calculations/MinMaxValues/MinMax.sip."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min_sip, "maximum": 3*np.nanmean(changes_sip)},json_file)
    json_file.close()

    json_file = open("NetFlow/Entropy/Calculations/MinMaxValues/MinMax.sip_rate."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min_sip_r, "maximum": 3*np.nanmean(changes_sip_r)},json_file)
    json_file.close()

    json_file = open("NetFlow/Entropy/Calculations/MinMaxValues/MinMax.dip."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min_dip, "maximum": 3*np.nanmean(changes_dip)},json_file)
    json_file.close()

    json_file = open("NetFlow/Entropy/Calculations/MinMaxValues/MinMax.dip_rate."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min_dip_r, "maximum": 3*np.nanmean(changes_dip_r)},json_file)
    json_file.close()

    json_file = open("NetFlow/Entropy/Calculations/MinMaxValues/MinMax.flow."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min_f, "maximum": 3*np.nanmean(changes_f)},json_file)
    json_file.close()

    json_file = open("NetFlow/Entropy/Calculations/MinMaxValues/MinMax.f_rate."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min_f_r, "maximum": 3*np.nanmean(changes_f_r)},json_file)
    json_file.close()

    json_file = open("NetFlow/Entropy/Calculations/MinMaxValues/MinMax.nf."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min_nf, "maximum": 3*np.nanmean(changes_nf)},json_file)
    json_file.close()

    json_file = open("NetFlow/Entropy/Calculations/MinMaxValues/MinMax.packet_size."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min_PS, "maximum": 3*np.nanmean(changes_PS)},json_file)
    json_file.close()

    json_file = open("NetFlow/Entropy/Calculations/MinMaxValues/MinMax.packet_size_r."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min_PS_r, "maximum": 3*np.nanmean(changes_PS_r)},json_file)
    json_file.close()
    print(np.nanmean(changes_ICMP_ratio))
    json_file = open("NetFlow/Threshold/Calculations/MinMaxValues/MinMax.icmp_ratio."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min(changes_ICMP_ratio), "maximum": 3*np.nanmean(changes_ICMP_ratio)},json_file)
    json_file.close()
    print(np.nanmean(changes_ICMP_packets))
    json_file = open("NetFlow/Threshold/Calculations/MinMaxValues/MinMax.icmp_packets."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min(changes_ICMP_packets), "maximum": 3*np.nanmean(changes_ICMP_packets)},json_file)
    json_file.close()

    json_file = open("NetFlow/Threshold/Calculations/MinMaxValues/MinMax.packets."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min_packets, "maximum": 3*np.nanmean(changes_packets)},json_file)
    json_file.close()

    json_file = open("NetFlow/Threshold/Calculations/MinMaxValues/MinMax.bytes."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min_bytes, "maximum": 3*np.nanmean(changes_bytes)},json_file)
    json_file.close()

findMinMaxMetricCalc("/home/linneafg/silk-data/RawDataFromFilter/oslo-gw1/all7weeks-sorted.rw", "2010-12-27 00:00:00", "2011-02-14 00:00:00", timedelta(minutes = 1), timedelta(minutes = 5), 10)
findMinMaxMetricCalc("/home/linneafg/silk-data/RawDataFromFilter/oslo-gw1/all7weeks-sorted.rw", "2010-12-27 00:00:00", "2011-02-14 00:00:00", timedelta(minutes = 1), timedelta(minutes = 15), 10)