import pickle
import pandas as pd
from ..GetData import *
from StructureData import *
from datetime import datetime
from MakePlot import *

def detection(start, stop, systemId, if_name, fields):
    df = pd.read_pickle("TelemetryKmeans/Data/TestingDataEntropy.pkl")
    timeStamps, measurements = structureData(df)
    kmeans = pickle.load(open("TelemetryKmeans/Models/MLmodelEntropy.pkl", 'rb'))
    prediction = kmeans.predict(measurements)
    count0 = 0 
    count1 = 0

    time0 = []
    time1 = []

    entropy0 = []
    entropy1 = []

    entropyR0 = []
    entropyR1 = []

    for i in range(len(prediction)):
        if prediction[i] == 0:
            time0.append(timeStamps[i])
            entropy0.append(measurements[i][0])
            entropyR0.append(measurements[i][1])

            time1.append(timeStamps[i])
            entropy1.append(None)
            entropyR1.append(None)

            count0 +=1
        elif prediction[i] == 1:
            time1.append(timeStamps[i])
            entropy1.append(measurements[i][0])
            entropyR1.append(measurements[i][1])

            time0.append(timeStamps[i])
            entropy0.append(None)
            entropyR0.append(None)

            count1 += 1
    print(count0)
    print(count1)
    makePlot(entropy0, time0, "Entropy in cluster 0")
    makePlot(entropy1, time1, "Entropy in cluster 1")

    makePlot(entropyR0, time0, "Entropy rate in cluster 0")
    makePlot(entropyR1, time1, "Entropy rate in cluster 1")
    

start = "2022-10-13 00:00:00"
stop = "2022-10-20 00:00:00"
systemId = "trd-gw"
if_name = "xe-0/1/0"
fields = ["egress_queue_info__0__avg_buffer_occupancy", "egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets"]

detection(start, stop, systemId, if_name, fields)