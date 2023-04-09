from datetime import datetime,timedelta
import numpy as np
from HelperFunctions.GetData import *
from HelperFunctions.GeneralizedEntropy import *
from HelperFunctions.Distributions import *

'''
    Calculates entropy, packet and byte count and alerts in case of an anomaly
    Input:  start:                  string, indicating the start time of the data to detect on
            stop:                   string, indicating the stop time of the data to detect on
            systemId:               string, name of the system to collect and calculate on  
            if_name:                string, interface name, 
            interval:               timedelta object, size of the sliding window which the calculation is made on,
            frequency:              timedelta object, frequency of metric calculation,
            windowSize:             int, represents a multiplier of frequency, how far back we want to compare the value with
            thresholdEntropy:       float, values over this threshold will cause an alert
            thresholdEntropyRate:   float, values over this threshold will cause an alert
            thresholdPackets:       float, values over this threshold will cause an alert
            thresholdBytes:         float, values over this threshold will cause an alert
            attackDate:             string, date of the attack the calculations are made on
'''
def detectionEntropyTelemetry(start, stop, systemId, if_name, interval, frequency, windowSize, thresholdEntropy, thresholdEntropyRate, thresholdPackets, thresholdBytes, attackDate):
    #Open file to write alerts to
    f = open("Detections/Entropy/Telemetry/EntropyPacketSize."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_rate = open("Detections/Entropy/Telemetry/EntropyRatePacketSize."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_pkts = open("Detections/Threshold/Telemetry/NumberOfPackets."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_bytes = open("Detections/Threshold/Telemetry/NumberOfBytes."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    f.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    f_rate.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    f_pkts.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    f_bytes.write("Time,Change,Value,Mean_last_"+ str(windowSize))

    #Instantiate empty arrays for the calculated values
    packetSizeArray = []
    packetSizeRateArray = []
    packetNumberArray = []
    bytesArray = []

    #Makes datetime objects of the input times
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    intervalTime = (stopTime - startTime).total_seconds()/frequency.total_seconds()

    #Loop for every minute in a week
    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + interval
        #Get data for a specified time interval
        df = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),systemId, if_name, ["egress_stats__if_1sec_octets","egress_stats__if_1sec_pkts"])
        if df.empty:
            packetSizeArray.append(np.nan)
            packetSizeRateArray.append(np.nan)
            packetNumberArray.append(np.nan)
            bytesArray.append(np.nan)
            startTime = startTime + frequency
            continue
        dfEgressBytes = df["egress_stats__if_1sec_octets"].to_numpy()
        dfEgressPackets = df["egress_stats__if_1sec_pkts"].to_numpy()

        #If there is not enough datapoints the minute is skipped
        if len(dfEgressBytes) < 10 or len(dfEgressPackets) < 10:
            packetSizeArray.append(np.nan)
            packetSizeRateArray.append(np.nan)
            packetNumberArray.append(np.nan)
            bytesArray.append(np.nan)
            startTime = startTime + frequency
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
        packetNumberArray.append(sum(dfEgressPackets))
        bytesArray.append(sum(dfEgressBytes))

        #If there is not enough stored values to compare with we skip the detection
        if i < windowSize:
            #Push the start time by the specified frequency
            startTime = startTime + frequency
            continue
        
        #Compare the difference of each metric with a threshold
        if packetSizeArray !=  np.nan:
            if abs(packetSizeArray[i] - np.nanmean(packetSizeArray[i-windowSize: i-1])) > thresholdEntropy:
                f.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(packetSizeArray[i] - np.nanmean(packetSizeArray[i-windowSize: i-1]))) + "," + str(packetSizeArray[i]) + "," + str(np.nanmean(packetSizeArray[i-windowSize: i-1])))

        if packetSizeRateArray !=  np.nan:
            if abs(packetSizeRateArray[i] - np.nanmean(packetSizeRateArray[i-windowSize: i-1])) > thresholdEntropyRate:
                f_rate.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(packetSizeRateArray[i] - np.nanmean(packetSizeRateArray[i-windowSize: i-1]))) + "," + str(packetSizeRateArray[i]) + "," + str(np.nanmean(packetSizeRateArray[i-windowSize: i-1])))

        if packetNumberArray !=  np.nan:
            if abs(packetNumberArray[i] - np.nanmean(packetNumberArray[i-windowSize: i-1])) > thresholdPackets:
                f_pkts.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(packetNumberArray[i] - np.nanmean(packetNumberArray[i-windowSize: i-1]))) + "," + str(packetNumberArray[i]) + "," + str(np.nanmean(packetNumberArray[i-windowSize: i-1])))

        if bytesArray !=  np.nan:
            if abs(bytesArray[i] - np.nanmean(bytesArray[i-windowSize: i-1])) > thresholdBytes:
                f_bytes.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(bytesArray[i] - np.nanmean(bytesArray[i-windowSize: i-1]))) + "," + str(bytesArray[i]) + "," + str(np.nanmean(bytesArray[i-windowSize: i-1])))

        '''
        #CHATGPT VERSION
        # Define a list of tuples where each tuple contains the array, threshold value,
        # and the file object to write the output to.
        data = [
            (packetSizeArray, thresholdEntropy, f),
            (packetSizeRateArray, thresholdEntropyRate, f_rate),
            (packetNumberArray, thresholdPackets, f_pkts),
            (bytesArray, thresholdBytes, f_bytes)
        ]

        # Loop through the list of tuples and process each array accordingly.
        for arr, threshold, file_obj in data:
            if arr is not None and not np.isnan(arr):
                if abs(arr[i] - np.nanmean(arr[i-windowSize:i-1])) > threshold:
                    file_obj.write("\n" + startTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(arr[i] - np.nanmean(arr[i-windowSize:i-1]))) + "," + str(arr[i]) + "," + str(np.nanmean(arr[i-windowSize:i-1])))

        '''

        #Push the start time by the specified frequency
        startTime = startTime + frequency

    f.close()
    f_rate.close()
    f_pkts.close()
    f_bytes.close()

'''start = "2022-09-21 01:00:00"
stop = "2022-09-22 00:00:00"
systemId = "trd-gw"
if_name = "xe-0/1/0"
interval = timedelta(minutes = 5)
frequency = timedelta(minutes = 1)
attackDate = "21.09"
windowSize = 10
thresholdEntropy = 0.5
thresholdEntropyRate = 0.005
thresholdPackets = 1000
thresholdBytes = 1000
detectionEntropyTelemetry(systemId, if_name, start, stop, frequency, interval, windowSize, thresholdEntropy, thresholdEntropyRate, thresholdPackets, thresholdBytes, attackDate)'''