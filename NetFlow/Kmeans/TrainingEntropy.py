from sklearn.cluster import KMeans
from .GetData import *
from HelperFunctions.StructureData import *
import pickle

def trainingEntropy(silkFile, start, stop, systemId, frequency, interval,attackDate):
    df = getEntropyData(silkFile, start, stop, frequency, interval)
    df.to_pickle("NetFlow/Kmeans/RawData/TrainingDataEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    #df = pd.read_pickle("NetFlow/Kmeans/RawData/TrainingDataEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    timeStamps, measurements =structureDataEntropy(df)

    kmeans = KMeans(n_clusters=2, random_state=0, n_init="auto").fit(measurements)
    pickle.dump(kmeans, open("NetFlow/Kmeans/Models/MLmodelEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl", 'wb'))

'''silkFile="/home/linneafg/silk-data/RawDataFromFilter/two-hours-2011-01-01_10-11-sorted.rw"
start = "2011-01-01 10:00:00"
stop = "2011-01-01 12:00:00"
systemId = "oslo-gw"
frequency = timedelta(minutes=1)
interval = timedelta(minutes=5)
trainingEntropy(silkFile, start, stop, systemId, frequency, interval)'''