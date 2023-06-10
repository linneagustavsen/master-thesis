from datetime import datetime,timedelta
import json
from pathlib import Path
import numpy as np
from HelperFunctions.GetData import *
from HelperFunctions.GeneralizedEntropy import *
from HelperFunctions.Distributions import *
from HelperFunctionsTelemetry.GetDataTelemetry import getData, getDataBytes, getDataPackets

'''
    Calculates entropy and writes calculations to file
    Input:  start:      string, indicating the start time of the data to detect on
            stop:       string, indicating the stop time of the data to detect on
            systemId:   string, name of the system to collect and calculate on  
            if_name:    string, interface name, 
            interval:   timedelta object, size of the sliding window which the calculation is made on,
            frequency:  timedelta object, frequency of metric calculation,
            attackDate: string, date of the attack the calculations are made on
'''

def findMinMaxEntropyTelemetry(start, stop, systemId, interval, frequency):

    #Instantiate empty arrays for the calculated values
    packetSizeArrayin = []
    packetSizeRateArrayin = []
    packetSizeArrayout = []
    packetSizeRateArrayout = []
    packetNumberArrayin = []
    bytesArrayin = []
    packetNumberArrayout = []
    bytesArrayout = []

    changesPSin = []
    changesPS_rin = []
    changesPacketsin = []
    changesBytesin = []

    changesPSout = []
    changesPS_rout = []
    changesPacketsout = []
    changesBytesout = []
    j = 0

    
    #Makes datetime objects of the input times
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    intervalTime = (stopTime - startTime).total_seconds()/frequency.total_seconds()
    #Loop for every minute in a week
    for i in range(math.ceil(intervalTime)):
        if i % 100== 0:
            print("Iteration:", i)
        stopTime = startTime + interval
        #Get data for a specified time interval
        df_bytes_ingress = getDataBytes(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), "mars", systemId, "in")
        df_bytes_egress = getDataBytes(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), "mars", systemId, "out")
        df_packets_ingress = getDataPackets(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), "mars", systemId, "in")
        df_packets_egress = getDataPackets(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), "mars", systemId, "out")
        #If there is no data for this interval we skip the calculations
        if df_bytes_ingress.empty or df_packets_ingress.empty or df_bytes_egress.empty or df_packets_egress.empty:
            startTime = startTime + frequency
            continue
        df_bytes_ingress = df_bytes_ingress["bytes"].to_numpy()
        df_packets_ingress = df_packets_ingress["packets"].to_numpy()
        df_bytes_egress = df_bytes_egress["bytes"].to_numpy()
        df_packets_egress = df_packets_egress["packets"].to_numpy()

        #Find the probability distribution based on how big the packets are this time interval
        PiPS,nps = packetSizeDistribution(df_bytes_ingress, df_packets_ingress)
        #Calculate the generalized entropy of this distribution
        entropyPacketSize = generalizedEntropy(10, PiPS)
        packetSizeArrayin.append(entropyPacketSize)
        #Calculate the generalized entropy rate of this distribution
        packetSizeRateArrayin.append(entropyPacketSize/nps)

        #Find the probability distribution based on how big the packets are this time interval
        PiPS,nps = packetSizeDistribution(df_bytes_egress, df_packets_egress)
        #Calculate the generalized entropy of this distribution
        entropyPacketSize = generalizedEntropy(10, PiPS)
        packetSizeArrayout.append(entropyPacketSize)
        #Calculate the generalized entropy rate of this distribution
        packetSizeRateArrayout.append(entropyPacketSize/nps)

        #Store the number of packets and bytes this time interval
        packetNumberArrayin.append(sum(df_packets_ingress))
        bytesArrayin.append(sum(df_bytes_ingress))

        packetNumberArrayout.append(sum(df_packets_egress))
        bytesArrayout.append(sum(df_bytes_egress))

        
        if j >= 10:
            changePS = abs(packetSizeArrayin[j] - np.nanmean(packetSizeArrayin[j-10: j-1]))
            changesPSin.append(changePS)

            changePS_r = abs(packetSizeRateArrayin[j] - np.nanmean(packetSizeRateArrayin[j-10: j-1]))
            changesPS_rin.append(changePS_r)

            changePackets = abs(packetNumberArrayin[j] - np.nanmean(packetNumberArrayin[j-10: j-1]))
            changesPacketsin.append(changePackets)

            changeBytes = abs(bytesArrayin[j] - np.nanmean(bytesArrayin[j-10: j-1]))
            changesBytesin.append(changeBytes)


            changePS = abs(packetSizeArrayout[j] - np.nanmean(packetSizeArrayout[j-10: j-1]))
            changesPSout.append(changePS)

            changePS_r = abs(packetSizeRateArrayout[j] - np.nanmean(packetSizeRateArrayout[j-10: j-1]))
            changesPS_rout.append(changePS_r)

            changePackets = abs(packetNumberArrayout[j] - np.nanmean(packetNumberArrayout[j-10: j-1]))
            changesPacketsout.append(changePackets)

            changeBytes = abs(bytesArrayout[j] - np.nanmean(bytesArrayout[j-10: j-1]))
            changesBytesout.append(changeBytes)

        #Push the start time by the specified frequency
        startTime = startTime + frequency
        j += 1

    json_file = open("Telemetry/Entropy/Calculations/MinMaxValues/MinMax.packet_size_ingress."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min(changesPSin), "maximum": 3*np.nanmean(changesPSin)},json_file)
    json_file.close()
    json_file = open("Telemetry/Entropy/Calculations/MinMaxValues/MinMax.packet_size_rate_ingress."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min(changesPS_rin), "maximum": 3*np.nanmean(changesPS_rin)},json_file)
    json_file.close()
    json_file = open("Telemetry/Threshold/Calculations/MinMaxValues/MinMax.packets_ingress."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min(changesPacketsin), "maximum":  3*np.nanmean(changesPacketsin)},json_file)
    json_file.close()
    json_file = open("Telemetry/Threshold/Calculations/MinMaxValues/MinMax.bytes_ingress."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min(changesBytesin), "maximum":  3*np.nanmean(changesBytesin)},json_file)
    json_file.close()


    json_file = open("Telemetry/Entropy/Calculations/MinMaxValues/MinMax.packet_size_egress."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min(changesPSout), "maximum": 3*np.nanmean(changesPSout)},json_file)
    json_file.close()
    json_file = open("Telemetry/Entropy/Calculations/MinMaxValues/MinMax.packet_size_rate_egress."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min(changesPS_rout), "maximum": 3*np.nanmean(changesPS_rout)},json_file)
    json_file.close()
    json_file = open("Telemetry/Threshold/Calculations/MinMaxValues/MinMax.packets_egress."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min(changesPacketsout), "maximum":  3*np.nanmean(changesPacketsout)},json_file)
    json_file.close()
    json_file = open("Telemetry/Threshold/Calculations/MinMaxValues/MinMax.bytes_egress."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": min(changesBytesout), "maximum":  3*np.nanmean(changesBytesout)},json_file)
    json_file.close()
'''findMinMaxEntropyTelemetry("oslo-gw1", timedelta(minutes=5), timedelta(minutes=1))
findMinMaxEntropyTelemetry("oslo-gw1", timedelta(minutes=10), timedelta(minutes=1))
findMinMaxEntropyTelemetry("oslo-gw1", timedelta(minutes=15), timedelta(minutes=1))'''