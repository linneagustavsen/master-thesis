from sklearn.cluster import KMeans
import numpy as np
from datetime import datetime
from HelperFunctions.GetData import *
from StructureData import *
import pandas as pd
import pickle

def training(start, stop, systemId, if_name):
    columTitles = ["egress_queue_info__0__avg_buffer_occupancy", "egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets","entropy_packet_size", "entropy_rate_packet_size"]
    
    fields = ["egress_queue_info__0__avg_buffer_occupancy", "egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets"]

    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    #df = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),systemId, if_name, fields)

    #df.to_pickle("Telemetry/RandomForest/Data/RawTrainingData.pkl")
    df = pd.read_pickle("Telemetry/Kmeans/Data/TrainingData.pkl")
    timeStamps, measurements = structureData(df)
    data = np.empty((len(timeStamps),len(columTitles)))
    print("Structured Data")
    #packetSizeArray, packetSizeRateArray, timeArray = getEntropyData(systemId, if_name, startTime, stopTime)
    entropy_df = pd.read_pickle("Telemetry/Kmeans/Data/TrainingDataEntropy.pkl")   
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
            indexArray = np.where(entropy_timeStamps == timestamp.strftime("%Y-%m-%d %H:%M"))
            if len(indexArray[0]) == 0:
                continue
            indexInTimeArray = indexArray[0][0]
            lastYear = curYear
            lastMonth = curMonth
            lastDay = curDay
            lastHour = curHour
            lastMinute = curMinute
            
        entropyPacketSize = entropy_measurements[indexInTimeArray][0]
        entropyRatePacketSize = entropy_measurements[indexInTimeArray][1]
        curMeasurements = measurements[i]

        newMeasurements = np.array([entropyPacketSize, entropyRatePacketSize])

        curMeasurements = np.concatenate((curMeasurements,newMeasurements), axis=None)

        data[i] = curMeasurements
    
    trainingSet = pd.DataFrame(data, columns=columTitles)
    trainingSet.to_pickle("Telemetry/Kmeans/Data/TrainingDataCombined.pkl")
    print(trainingSet.head)



    kmeans = KMeans(n_clusters=2, random_state=0, n_init="auto").fit(trainingSet)
    pickle.dump(kmeans, open("Telemetry/Kmeans/Models/MLmodelCombined.pkl", 'wb'))

start = "2022-09-22 00:00:00"
stop = "2022-10-13 00:00:00"
systemId = "trd-gw"
if_name = "xe-0/1/0"
#fields = ["egress_queue_info__0__avg_buffer_occupancy", "egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets"]

training(start, stop, systemId, if_name)