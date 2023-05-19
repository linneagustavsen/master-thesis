from datetime import datetime, timedelta
import math
import os
from NetFlow.Kmeans.CalculationsKmeans import kmeansCalculation
from NetFlow.Kmeans.CalculationsKmeansCombined import kmeansCombinedCalculation
from NetFlow.Kmeans.CalculationsKmeansEntropy import kmeansEntropyCalculation
'''
    Function to get k-means calculations on NetFlow data
    Input:  baseFile:       string, raw base file with SiLK NetFlow records,
            systems:        list of strings, systems the calculations will be made on,
            start:          string, indicates the start time of the records,
            stop:           string, indicates the stop time of the records,
            startCombined:  string, indicates the start time of the records when doing K-means on both entropy and metrics,
            stopCombined:   string, indicates the stop time of the records when doing K-means on both entropy and metrics,
            frequency:      timedelta object, frequency of metric calculation,
            interval:       timedelta object, size of the sliding window which the calculation is made on,
            pathToRawFiles: string, path to the SiLK NetFlow records,
            attackDate:     string, date of the attack the calculations are made on
'''
def kmeansMain(baseFile, systems, start, stop, clusterFrequency, frequency, intervals, pathToRawFiles, attackDate):        
    #Kmeans
    for systemId in systems:
        print(systemId)
        silkFile = pathToRawFiles+systemId + "/"+ baseFile
        #normal
        kmeansCalculation(silkFile, start, stop, clusterFrequency, systemId, attackDate)
        print("Finished kmeans flow field calculations")
        
        for interval in intervals:
            print(str(interval))
            #entropy
            kmeansEntropyCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
            print("Finished kmeans entropy calculations")
            if interval != timedelta(minutes=15):
                #combined    
                kmeansCombinedCalculation(silkFile, start, stop, clusterFrequency, frequency, systemId, interval, attackDate)
                print("Finished kmeans flow field  and entropy calculations")
            else:
                #combined    
                kmeansCombinedCalculation(silkFile, start, stop, timedelta(minutes=30), frequency, systemId, interval, attackDate)
                print("Finished kmeans flow field  and entropy calculations")

            if os.path.exists("NetFlow/Kmeans/DataSets/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"):
                os.remove("NetFlow/Kmeans/DataSets/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy")
            else:
                print("The file NetFlow/Kmeans/DataSets/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy does not exist") 

        startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
        stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
        intervalTime = (stopTime - startTime).total_seconds()/timedelta(minutes=15).total_seconds()
    
        for i in range(math.ceil(intervalTime)):
            stopTime = startTime + timedelta(minutes=15)
            if os.path.exists("NetFlow/Kmeans/DataSets/Fields.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".npy"):
                os.remove("NetFlow/Kmeans/DataSets/Fields.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".npy")
            else:
                print("The file NetFlow/Kmeans/DataSets/Fields.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".npy does not exist") 
            startTime += timedelta(minutes=15)

#Attack 2
baseFile="2023-03-17_11-14-sorted.rw"        
systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
start = "2023-03-17 11:00:00"
stop = "2023-03-17 14:00:00"
frequency = timedelta(minutes = 1)
intervals = [timedelta(minutes = 5), timedelta(minutes = 10), timedelta(minutes = 15)]
clusterFrequency = timedelta(minutes = 15)
pathToRawFiles="/data/master-dump/fresh-netflow-data/master-dump/"
attackDate="17.03.23"

kmeansMain(baseFile, systems, start, stop, clusterFrequency, frequency, intervals, pathToRawFiles, attackDate)

baseFile="2023-03-24_14-18-sorted.rw"         
start = "2023-03-24 14:00:00"
stop = "2023-03-24 18:00:00"
attackDate="24.03.23"
kmeansMain(baseFile, systems, start, stop, clusterFrequency, frequency, intervals, pathToRawFiles, attackDate)      
