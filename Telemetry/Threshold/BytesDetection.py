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
            thresholdBytes:         float, values over this threshold will cause an alert
            attackDate:             string, date of the attack the calculations are made on
'''

def detectionBytesTelemetry(start, stop, systemId, if_name, interval, frequency, windowSize, thresholdBytes, attackDate):
    #Open file to write alerts to
    f_bytes = open("Detections/Threshold/Telemetry/NumberOfBytes."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    f_bytes.write("Time,Change,Value,Mean_last_"+ str(windowSize))

    #Instantiate empty arrays for the calculated values
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
            startTime = startTime + frequency
            bytesArray.append(np.nan)
            continue
        dfEgressBytes = df["egress_stats__if_1sec_octets"].to_numpy()
        dfEgressPackets = df["egress_stats__if_1sec_pkts"].to_numpy()

        #If there is not enough datapoints the minute is skipped
        if len(dfEgressBytes) < 10 or len(dfEgressPackets) < 10:
            startTime = startTime + frequency
            bytesArray.append(np.nan)
            continue

        bytesArray.append(sum(dfEgressBytes))

        #If there is not enough stored values to compare with we skip the detection
        if i < windowSize:
            #Push the start time by the specified frequency
            startTime = startTime + frequency
            continue
        
        #Compare the difference of each metric with a threshold
        if bytesArray !=  np.nan:
            if abs(bytesArray[i] - np.nanmean(bytesArray[i-windowSize: i-1])) > thresholdBytes:
                f_bytes.write("\n" + stopTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(bytesArray[i] - np.nanmean(bytesArray[i-windowSize: i-1]))) + "," + str(bytesArray[i]) + "," + str(np.nanmean(bytesArray[i-windowSize: i-1])))

        #Push the start time by the specified frequency
        startTime = startTime + frequency

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
detectionBytesTelemetry(systemId, if_name, start, stop, frequency, interval, windowSize, thresholdEntropy, thresholdEntropyRate, thresholdPackets, thresholdBytes, attackDate)'''