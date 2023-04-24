from datetime import datetime,timedelta
import json
from pathlib import Path
import numpy as np
from HelperFunctions.GetData import *
from HelperFunctions.GeneralizedEntropy import *
from HelperFunctions.Distributions import *
from HelperFunctions.IsAttack import isAttack
from HelperFunctionsTelemetry.GetDataTelemetry import getData

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

def findMinMaxEntropyTelemetry(systemId, if_name, interval, frequency):

    #Instantiate empty arrays for the calculated values
    packetSizeArray = []
    packetSizeRateArray = []
    packetNumberArray = []
    bytesArray = []

    maxPS = 0
    minPS = 1000000000000000000

    maxPS_r = 0
    minPS_r = 1000000000000000000

    maxPackets = 0
    minPackets = 1000000000000000000

    maxBytes = 0
    minBytes = 1000000000000000000

    counter = 0
    start = ['2022-09-22 00:00:00', '2023-01-25 00:00:00', '2023-02-23 00:00:00']
    stop = ['2022-10-22 00:00:00', '2023-02-23 00:00:00', '2023-03-07 00:00:00']

    buckets = ["october", "february", "mars"]
    for bucket in buckets:
        #Makes datetime objects of the input times
        startTime = datetime.strptime(start[counter], '%Y-%m-%d %H:%M:%S')
        stopTime = datetime.strptime(stop[counter], '%Y-%m-%d %H:%M:%S')
        
        intervalTime = (stopTime - startTime).total_seconds()/frequency.total_seconds()
        #Loop for every minute in a week
        for i in range(math.ceil(intervalTime)):
            stopTime = startTime + interval
            #Get data for a specified time interval
            df = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), bucket, systemId, if_name, ["egress_stats__if_1sec_octets","egress_stats__if_1sec_pkts"])
            #If there is no data for this interval we skip the calculations
            if df.empty:
                startTime = startTime + frequency
                continue
            dfEgressBytes = df["egress_stats__if_1sec_octets"].to_numpy()
            dfEgressPackets = df["egress_stats__if_1sec_pkts"].to_numpy()

            #Find the probability distribution based on how big the packets are this time interval
            PiPS,nps = packetSizeDistribution(dfEgressBytes, dfEgressPackets)
            #Calculate the generalized entropy of this distribution
            entropyPacketSize = generalizedEntropy(10, PiPS)
            packetSizeArray.append(entropyPacketSize)
            #Calculate the generalized entropy rate of this distribution
            packetSizeRateArray.append(entropyPacketSize/nps)

            #Store the number of packets and bytes this time interval
            packetNumberArray.append(sum(dfEgressPackets))
            bytesArray.append(sum(dfEgressBytes))

            
            if i >= 10:
                changePS = abs(packetSizeArray[i] - np.nanmean(packetSizeArray[i-10: i-1]))
                if changePS > maxPS:
                    maxPS = changePS
                elif changePS < minPS:
                    minPS = changePS 

                changePS_r = abs(packetSizeRateArray[i] - np.nanmean(packetSizeRateArray[i-10: i-1]))
                if changePS_r > maxPS_r:
                    maxPS_r = changePS_r
                elif changePS_r < minPS_r:
                    minPS_r = changePS_r 

                changePackets = abs(packetNumberArray[i] - np.nanmean(packetNumberArray[i-10: i-1]))
                if changePackets > maxPackets:
                    maxPackets = changePackets
                elif changePackets < minPackets:
                    minPackets = changePackets 

                changeBytes = abs(bytesArray[i] - np.nanmean(bytesArray[i-10: i-1]))
                if changeBytes > maxBytes:
                    maxBytes = changeBytes
                elif changeBytes < minBytes:
                    minBytes = changeBytes 
            #Push the start time by the specified frequency
            startTime = startTime + frequency
            i += 1
        counter += 1

    json_file = open("Telemetry/Entropy/Calculations/MinMax.MinMax.packet_size."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": minPS, "maximum": maxPS},json_file)
    json_file.close()
    json_file = open("Telemetry/Entropy/Calculations/MinMax.MinMax.packet_size_rate."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": minPS_r, "maximum": maxPS_r},json_file)
    json_file.close()
    json_file = open("Telemetry/Threshold/Calculations/MinMax.packets."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": minPackets, "maximum": maxPackets},json_file)
    json_file.close()
    json_file = open("Telemetry/Threshold/Calculations/MinMax.bytes."+ str(int(interval.total_seconds())) +".json", "w")
    json.dump({"minimum": minBytes, "maximum": maxBytes},json_file)
    json_file.close()

'''
start = "2022-09-21 01:00:00"
stop = "2022-09-22 00:00:00"
systemId = "trd-gw"
if_name = "xe-0/1/0"
interval = timedelta(minutes = 5)
frequency = timedelta(minutes = 1)
attackDate = "21.09"
calculationEntropyTelemetry(start, stop, systemId, if_name, interval, frequency, attackDate)'''
