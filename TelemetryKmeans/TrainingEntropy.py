from sklearn.cluster import KMeans
import numpy as np
from datetime import datetime
from HelperFunctions.GetData import *
from StructureData import *
import pandas as pd
import pickle

def training(start, stop, systemId, if_name):
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    df = getEntropyData(startTime, stopTime, systemId, if_name)
    df.to_pickle("TelemetryKmeans/Data/TrainingDataEntropy.pkl")
    #df = pd.read_pickle("TelemetryKmeans/data.pkl")  
    timeStamps, measurements = structureData(df)


    kmeans = KMeans(n_clusters=2, random_state=0, n_init="auto").fit(measurements)
    pickle.dump(kmeans, open("TelemetryKmeans/Models/MLmodelEntropy.pkl", 'wb'))

start = "2022-09-22 00:00:00"
stop = "2022-10-13 00:00:00"
systemId = "trd-gw"
if_name = "xe-0/1/0"
#fields = ["egress_queue_info__0__avg_buffer_occupancy", "egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets"]

training(start, stop, systemId, if_name)