import pickle
import pandas as pd
from HelperFunctions.GetData import *
from StructureData import *
from datetime import datetime

def detection(start, stop, systemId, if_name, fields):
    f0 = open("Telemetry/Kmeans/Data/Cluster0."+ str(systemId) + "." + str(if_name).replace("/","-") + ".csv", "a")
    f1 = open("Telemetry/Kmeans/Data/Cluster1."+ str(systemId) + "." + str(if_name).replace("/","-") + ".csv", "a")
    f0.write("Time, Values")
    f1.write("Time, Values")

    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    '''df = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),systemId, if_name, fields)
    df.to_pickle("Telemetry/Kmeans/Data/TestingData.pkl")  '''
    df = pd.read_pickle("Telemetry/Kmeans/Data/TestingData.pkl")
    timeStamps, measurements = structureData(df)
    kmeans = pickle.load(open("Telemetry/Kmeans/Models/MLmodel.pkl", 'rb'))
    prediction = kmeans.predict(measurements)
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