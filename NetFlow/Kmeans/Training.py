from sklearn.cluster import KMeans
import numpy as np
from datetime import datetime
import pandas as pd
import pickle
from GetData import *
from StructureData import *
def training(silkFile, start, stop, systemId):
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    '''
    trainingData = getData(silkFile)
'''
    #trainingData.to_pickle("NetFlow/Kmeans/RawData/TrainingData."+str(systemId)+ ".pkl")
    trainingData = pd.read_pickle("NetFlow/Kmeans/RawData/TrainingData."+str(systemId)+ ".pkl")
    sTime, eTime, measurements = structureData(trainingData)
    kmeans = KMeans(n_clusters=2, random_state=0, n_init="auto").fit(measurements)
    pickle.dump(kmeans, open("NetFlow/Kmeans/Models/MLmodel."+str(systemId)+ ".pkl", 'wb'))

silkFile="/home/linneafg/silk-data/RawDataFromFilter/two-hours-2011-01-01_10-11-sorted.rw"
start = "2011-01-01 10:00:00"
stop = "2011-01-01 12:00:00"
systemId="oslo-gw"
 
training(silkFile, start, stop,systemId)