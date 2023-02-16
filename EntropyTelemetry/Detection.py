from datetime import datetime,timedelta
import numpy as np
from GetData import *
from GeneralizedEntropy import *
from Distributions import *
import warnings
from influxdb_client.client.warnings import MissingPivotFunction

warnings.simplefilter("ignore", MissingPivotFunction)


'''
    Calculates entropy and other metrics and alerts in case of an anomaly
    Input:  system ID,
            interface name,
            start time as a string, 
            a detection frequency as a timedelta object,
            a aggregation interval as a timedelta object, 
            a window size of how far back we should compare the values
'''

def detection(systemId, if_name, start, frequency, interval, windowSize):
    #Open file to write alerts to
    f = open("EntropyTelemetry/Detections/EntropyPacketSize."+ str(systemId) + "." + str(if_name).replace("/","-") + ".txt", "a")
    f_rate = open("EntropyTelemetry/Detections/EntropyRatePacketSize."+ str(systemId) + "." + str(if_name).replace("/","-") + ".txt", "a")
    
    #Write the column titles to the files
    f.write("Time, Change, Value, Mean last "+ str(windowSize))
    f_rate.write("Time, Change, Value, Mean last "+ str(windowSize))

    #Instantiate empty arrays for the calculated values
    packetSizeArray = []
    packetSizeRateArray = []
    packetNumberArray = []
    bytesArray = []

    #Makes a datetime object of the input start time
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    
    #Loop for every minute in a week
    for i in range(10080):
        stopTime = startTime + interval
        #Get data for a specified time interval
        dfEgressBytes = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),systemId, if_name, "egress_stats__if_1sec_octets")
        dfEgressPackets = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),systemId, if_name, "egress_stats__if_1sec_pkts")
        #Push the start time by the specified frequency
        startTime = startTime + frequency

        #If there is not enough datapoints the minute is skipped
        if len(dfEgressBytes) <130 or len(dfEgressPackets) <130:
            packetSizeArray.append(np.nan)
            packetSizeRateArray.append(np.nan)
            packetNumberArray.append(np.nan)
            bytesArray.append(np.nan)
            continue

        #Find the probability distribution based on how big the packets are this time interval
        PiPS,nd = packetSizeDistribution(dfEgressBytes, dfEgressPackets)
        #Calculate the generalized entropy of this distribution
        entropyPacketSize = generalizedEntropy(10, PiPS)
        packetSizeArray.append(entropyPacketSize)

        #Calculate the generalized entropy rate of this distribution
        entropyRatePacketSize = entropyPacketSize/nd
        packetSizeRateArray.append(entropyRatePacketSize)

        #Store the number of packets and bytes this time interval
        packetNumberArray.append(sum(dfEgressPackets["_value"].to_numpy()))
        bytesArray.append(sum(dfEgressBytes["_value"].to_numpy()))

        #If there is not enough stored values to compare with we skip the detection
        if i < windowSize:
            continue
        
        #Compare the difference of each metric with a threshold
        if packetSizeArray !=  np.nan:
            if abs(packetSizeArray[i] - np.nanmean(packetSizeArray[i-windowSize: i-1])) > 1:
                f.write("\n" + str(startTime) + "," + str(abs(packetSizeArray[i] - np.nanmean(packetSizeArray[i-windowSize: i-1]))) + "," + str(packetSizeArray[i]) + "," + str(np.nanmean(packetSizeArray[i-windowSize: i-1])))

        if packetSizeRateArray !=  np.nan:
            if abs(packetSizeRateArray[i] - np.nanmean(packetSizeRateArray[i-windowSize: i-1])) > 0.015:
                f_rate.write("\n" + str(startTime) + "," + str(abs(packetSizeRateArray[i] - np.nanmean(packetSizeRateArray[i-windowSize: i-1]))) + "," + str(packetSizeRateArray[i]) + "," + str(np.nanmean(packetSizeRateArray[i-windowSize: i-1])))
    f.close()
    f_rate.close()

detection("trd-gw", "xe-0/1/0", "2022-10-13 00:00:00", timedelta(minutes = 1), timedelta(minutes = 5), 10)
