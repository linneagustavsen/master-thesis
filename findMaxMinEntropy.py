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

def findMinMaxEntropyTelemetry(systemId, interval, frequency):

    #Instantiate empty arrays for the calculated values
    packetSizeArray = []
    packetSizeRateArray = []
    packetNumberArray = []
    bytesArray = []

    minPS = 1000000000000000000

    minPS_r = 1000000000000000000

    minPackets = 1000000000000000000

    minBytes = 1000000000000000000

    changesPS = []
    changesPS_r = []
    changesPackets = []
    changesBytes = []

    counter = 0
    j = 0
    start = ['2022-09-22 00:00:00', '2023-01-25 00:00:00', '2023-02-23 00:00:00']
    stop = ['2022-10-22 00:00:00', '2023-02-23 00:00:00', '2023-03-07 00:00:00']

    buckets = ["october", "february", "mars"]
    for bucket in buckets:
        print("Starting bucket",bucket)
        #Makes datetime objects of the input times
        startTime = datetime.strptime(start[counter], '%Y-%m-%d %H:%M:%S')
        stopTime = datetime.strptime(stop[counter], '%Y-%m-%d %H:%M:%S')
        
        intervalTime = (stopTime - startTime).total_seconds()/frequency.total_seconds()
        #Loop for every minute in a week
        for i in range(math.ceil(intervalTime)):
            if i % 100== 0:
                print("Iteration:", i)
            stopTime = startTime + interval
            #Get data for a specified time interval
            df_bytes = getDataBytes(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), bucket, systemId)
            df_packets = getDataPackets(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), bucket, systemId)
            #If there is no data for this interval we skip the calculations
            if df_bytes.empty or df_packets.empty:
                startTime = startTime + frequency
                continue
            dfBytes = df_bytes["bytes"].to_numpy()
            dfPackets = df_packets["packets"].to_numpy()

            #Find the probability distribution based on how big the packets are this time interval
            PiPS,nps = packetSizeDistribution(dfBytes, dfPackets)
            #Calculate the generalized entropy of this distribution
            entropyPacketSize = generalizedEntropy(10, PiPS)
            packetSizeArray.append(entropyPacketSize)
            #Calculate the generalized entropy rate of this distribution
            packetSizeRateArray.append(entropyPacketSize/nps)

            #Store the number of packets and bytes this time interval
            packetNumberArray.append(sum(dfPackets))
            bytesArray.append(sum(dfBytes))

            
            if j >= 10:
                changePS = abs(packetSizeArray[j] - np.nanmean(packetSizeArray[j-10: j-1]))
                changesPS.append(changePS)
                if changePS < minPS:
                    minPS = changePS 

                changePS_r = abs(packetSizeRateArray[j] - np.nanmean(packetSizeRateArray[j-10: j-1]))
                changesPS_r.append(changePS_r)
                if changePS_r < minPS_r:
                    minPS_r = changePS_r 

                changePackets = abs(packetNumberArray[j] - np.nanmean(packetNumberArray[j-10: j-1]))
                changesPackets.append(changePackets)
                if changePackets < minPackets:
                    minPackets = changePackets 

                changeBytes = abs(bytesArray[j] - np.nanmean(bytesArray[j-10: j-1]))
                changesBytes.append(changeBytes)
                if changeBytes < minBytes:
                    minBytes = changeBytes 
            #Push the start time by the specified frequency
            startTime = startTime + frequency
            j += 1
        counter += 1

    json_file = open("Telemetry/Entropy/Calculations/MinMaxValues/MinMax.packet_size."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": minPS, "maximum": 3*np.nanmean(changesPS)},json_file)
    json_file.close()
    json_file = open("Telemetry/Entropy/Calculations/MinMaxValues/MinMax.packet_size_rate."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": minPS_r, "maximum": 3*np.nanmean(changesPS_r)},json_file)
    json_file.close()
    json_file = open("Telemetry/Threshold/Calculations/MinMaxValues/MinMax.packets."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": minPackets, "maximum":  3*np.nanmean(changesPackets)},json_file)
    json_file.close()
    json_file = open("Telemetry/Threshold/Calculations/MinMaxValues/MinMax.bytes."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": minBytes, "maximum":  3*np.nanmean(changesBytes)},json_file)
    json_file.close()

findMinMaxEntropyTelemetry("oslo-gw1", timedelta(minutes=5), timedelta(minutes=1))
findMinMaxEntropyTelemetry("oslo-gw1", timedelta(minutes=10), timedelta(minutes=1))
findMinMaxEntropyTelemetry("oslo-gw1", timedelta(minutes=15), timedelta(minutes=1))