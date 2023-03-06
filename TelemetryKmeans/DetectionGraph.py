import pickle
import pandas as pd
from HelperFunctions.GetData import *
from StructureData import *
from datetime import datetime
from MakePlot import *

def detection(start, stop, systemId, if_name, fields):
    df = pd.read_pickle("TelemetryKmeans/Data/TestingData.pkl")
    timeStamps, measurements = structureData(df)
    kmeans = pickle.load(open("TelemetryKmeans/Models/MLmodel.pkl", 'rb'))
    prediction = kmeans.predict(measurements)
    count0 = 0 
    count1 = 0

    time0 = []
    time1 = []

    queueA0 = []
    queueA1 = []

    queueC0 = []
    queueC1 = []

    pkts0 = []
    pkts1 = []

    bytes0 = []
    bytes1 = []

    for i in range(len(prediction)):
        if prediction[i] == 0:
            time0.append(timeStamps[i])
            queueA0.append(measurements[i][0])
            queueC0.append(measurements[i][1])
            pkts0.append(measurements[i][2])
            bytes0.append(measurements[i][3])

            time1.append(timeStamps[i])
            queueA1.append(None)
            queueC1.append(None)
            pkts1.append(None)
            bytes1.append(None)

            count0 +=1
        elif prediction[i] == 1:
            time1.append(timeStamps[i])
            queueA1.append(measurements[i][0])
            queueC1.append(measurements[i][1])
            pkts1.append(measurements[i][2])
            bytes1.append(measurements[i][3])

            time0.append(timeStamps[i])
            queueA0.append(None)
            queueC0.append(None)
            pkts0.append(None)
            bytes0.append(None)

            count1 += 1
    print(count0)
    print(count1)
    makePlot(queueA0, time0, "Average queue in cluster 0")
    makePlot(queueA1, time1, "Average queue in cluster 1")

    makePlot(queueC0, time0, "Current queue in cluster 0")
    makePlot(queueC1, time1, "Current queue in cluster 1")

    makePlot(pkts0, time0, "Packets per sec in cluster 0")
    makePlot(pkts1, time1, "Packets per sec in cluster 1")

    makePlot(bytes0, time0, "Bytes per sec in cluster 0")
    makePlot(bytes1, time1, "Bytes per sec in cluster 1")
    

start = "2022-10-13 00:00:00"
stop = "2022-10-20 00:00:00"
systemId = "trd-gw"
if_name = "xe-0/1/0"
fields = ["egress_queue_info__0__avg_buffer_occupancy", "egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets"]

detection(start, stop, systemId, if_name, fields)