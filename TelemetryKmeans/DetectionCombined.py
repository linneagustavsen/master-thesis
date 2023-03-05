import pickle
import pandas as pd
from GetData import *
from StructureData import *
from datetime import datetime

def detection(start, stop, systemId, if_name, fields):
    f0 = open("TelemetryKmeans/Data/Combined.Cluster0."+ str(systemId) + "." + str(if_name).replace("/","-") + ".txt", "a")
    f1 = open("TelemetryKmeans/Data/Combined.Cluster1."+ str(systemId) + "." + str(if_name).replace("/","-") + ".txt", "a")
    f0.write("Time, Values")
    f1.write("Time, Values")

    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    #df = getEntropyData(startTime, stopTime, systemId, if_name)
    #df.to_pickle("TelemetryKmeans/Data/TestingDataEntropy.pkl")
    df = pd.read_pickle("TelemetryKmeans/Data/TestingDataCombined.pkl")
    measurements = df.values

    timeStamps = pd.read_pickle("TelemetryKmeans/Data/TestingData.pkl")["_time"].to_numpy()
    kmeans = pickle.load(open("TelemetryKmeans/Models/MLmodelCombined.pkl", 'rb'))

    prediction = kmeans.predict(df)
    count0 = 0 
    count1 = 0
    for i in range(len(prediction)):
        if prediction[i] == 0:
            f0.write("\n"  + str(timeStamps[i]) + ", " +str(measurements[i]))
            count0 +=1
        elif prediction[i] == 1:
            f1.write("\n" + str(timeStamps[i]) + ", " +str(measurements[i]))
            count1 += 1
    print(count0)
    print(count1)
    
    f0.close()
    f1.close()

start = "2022-10-13 00:00:00"
stop = "2022-10-20 00:00:00"
systemId = "trd-gw"
if_name = "xe-0/1/0"
fields = ["egress_queue_info__0__avg_buffer_occupancy", "egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets"]

detection(start, stop, systemId, if_name, fields)