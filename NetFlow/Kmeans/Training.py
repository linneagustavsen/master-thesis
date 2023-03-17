from sklearn.cluster import KMeans
import pickle
from .GetData import *
from HelperFunctions.StructureData import *
def training(silkFile, systemId):
    
    trainingData = getData(silkFile)
    trainingData.to_pickle("NetFlow/Kmeans/RawData/TrainingData.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    #trainingData = pd.read_pickle("NetFlow/Kmeans/RawData/TrainingData.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    sTime, eTime, measurements = structureData(trainingData)
    kmeans = KMeans(n_clusters=2, random_state=0, n_init="auto").fit(measurements)
    pickle.dump(kmeans, open("NetFlow/Kmeans/Models/MLmodel.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl", 'wb'))
'''
silkFile="/home/linneafg/silk-data/RawDataFromFilter/twelve-hours-2011-01-01_08-19-sorted.rw"
start = "2011-01-01 08:00:00"
stop = "2011-01-01 20:00:00"
systemId="oslo-gw"
 
training(silkFile, start, stop,systemId)'''