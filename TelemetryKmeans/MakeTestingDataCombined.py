from GetData import *
from datetime import datetime,timedelta,date
import pandas as pd
from StructureData import *
import numpy as np
from Distributions import *
from GeneralizedEntropy import *
import math

def makeTrainingSet(systemId, if_name, start, stop):
    columTitles = ["egress_queue_info__0__avg_buffer_occupancy", "egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets","entropy_packet_size", "entropy_rate_packet_size"]
    
    fields = ["egress_queue_info__0__avg_buffer_occupancy", "egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets"]

    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    #df = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),systemId, if_name, fields)

    #df.to_pickle("RandomForest/RawTestingData.pkl")
    df = pd.read_pickle("TelemetryKmeans/TestingData.pkl")
    timeStamps, measurements = structureData(df)
    data = np.empty((len(timeStamps),len(columTitles) ))
    print("Structured Data")
    #packetSizeArray, packetSizeRateArray, timeArray = getEntropyData(systemId, if_name, startTime, stopTime)
    entropy_df = pd.read_pickle("TelemetryKmeans/TestingDataEntropy.pkl")  
    print(entropy_df.head)
    entropy_timeStamps, entropy_measurements = structureData(entropy_df)
    print(entropy_timeStamps)
    print("Got entropy data")

    now = datetime.now()

    lastYear = now.year
    lastMonth = now.month
    lastDay = now.day
    lastHour = now.hour
    lastMinute = now.minute
    
    print("Start loop")
    for i in range(len(timeStamps)):
        timestamp = timeStamps[i]
        if i % 10000 == 0:
            print(timestamp)
            print(data[i-1])
        curYear = timestamp.year
        curMonth = timestamp.month
        curDay = timestamp.day
        curHour = timestamp.hour
        curMinute = timestamp.minute
        
        if not (lastYear == curYear and lastMonth == curMonth and lastDay == curDay and lastHour == curHour and lastMinute == curMinute):
            lastYear = curYear
            lastMonth = curMonth
            lastDay = curDay
            lastHour = curHour
            lastMinute = curMinute

            indexArray = np.where(entropy_timeStamps == timestamp.strftime("%Y-%m-%d %H:%M"))
            if len(indexArray[0]) == 0:
                continue
            indexInTimeArray = indexArray[0][0]

        entropyPacketSize = entropy_measurements[indexInTimeArray][0]
        entropyRatePacketSize = entropy_measurements[indexInTimeArray][1]
        curMeasurements = measurements[i]

        newMeasurements = np.array([entropyPacketSize, entropyRatePacketSize])

        curMeasurements = np.concatenate((curMeasurements,newMeasurements), axis=None)

        data[i] = curMeasurements
    
    trainingSet = pd.DataFrame(data, columns=columTitles)
    trainingSet.to_pickle("TelemetryKmeans/TestingDataCombined.pkl")
    print(trainingSet.head)

start = "2022-10-13 00:00:00"
stop = "2022-10-20 00:00:00"
systemId = "trd-gw"
if_name = "xe-0/1/0"


makeTrainingSet(systemId, if_name, start, stop)