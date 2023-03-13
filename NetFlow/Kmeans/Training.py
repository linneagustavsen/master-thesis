from sklearn.cluster import KMeans
import numpy as np
from datetime import datetime
from silk import *
import pandas as pd
import pickle
from GetData import *
def training(silkFile, start, stop):
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    '''infile = silkfile_open(silkFile, READ)
    trainingData = getDataTraining(infile)
'''
    #trainingData.to_pickle("NetFlow/Kmeans/RawData/RawTrainingData.pkl")
    trainingData = pd.read_pickle("NetFlow/Kmeans/RawData/RawTrainingData.pkl")
    measurements = trainingData.values
    kmeans = KMeans(n_clusters=2, random_state=0, n_init="auto").fit(trainingData)
    pickle.dump(kmeans, open("NetFlow/Kmeans/Models/MLmodel.pkl", 'wb'))

silkFile="/home/linneafg/silk-data/RawDataFromFilter/two-hours-2011-01-01_10-11-sorted.rw"
start = "2011-01-10 00:00:00"
stop = "2011-01-11 00:00:00"
 
training(silkFile, start, stop)