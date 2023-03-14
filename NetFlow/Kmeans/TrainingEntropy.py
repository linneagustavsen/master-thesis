from sklearn.cluster import KMeans
import numpy as np
from datetime import datetime,timedelta
from GetData import *
from StructureData import *
import pandas as pd
import pickle

def training(silkFile, start, stop, systemId, frequency, interval):
    '''df = getEntropyData(silkFile, start, stop, frequency, interval)
    df.to_pickle("NetFlow/Kmeans/RawData/TrainingDataEntropy."+str(systemId)+ ".pkl")'''
    df = pd.read_pickle("NetFlow/Kmeans/RawData/TrainingDataEntropy."+str(systemId)+ ".pkl")
    print(df.head)
    measurements = df.values[:,1:]
    print(measurements)

    kmeans = KMeans(n_clusters=2, random_state=0, n_init="auto").fit(measurements)
    pickle.dump(kmeans, open("NetFlow/Kmeans/Models/MLmodelEntropy."+str(systemId)+ ".pkl", 'wb'))

silkFile="/home/linneafg/silk-data/RawDataFromFilter/two-hours-2011-01-01_10-11-sorted.rw"
start = "2011-01-01 10:00:00"
stop = "2011-01-01 12:00:00"
systemId = "oslo-gw"
frequency = timedelta(minutes=1)
interval = timedelta(minutes=5)
training(silkFile, start, stop, systemId, frequency, interval)