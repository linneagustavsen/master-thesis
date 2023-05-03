from datetime import timedelta
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
def kmeansMain(baseFile, systems, start, stop, clusterFrequency, frequency, interval, pathToRawFiles, attackDate):        
    #Kmeans
    for systemId in systems:
        print(str(interval))
        print(systemId)
        silkFile = pathToRawFiles+systemId + "/"+ baseFile
        #normal
        kmeansCalculation(silkFile, start, stop, clusterFrequency, systemId, attackDate)
        print("Finished kmeans flow field calculations")
        #entropy
        kmeansEntropyCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
        print("Finished kmeans entropy calculations")
        #combined
        #testingSet = makeDataSetKmeansNetFlow(silkFile, startCombined, stopCombined, systemId, frequency, interval, attackDate)
        #print("Finished with making combined testing data")
        kmeansCombinedCalculation(silkFile, start, stop, clusterFrequency, frequency, systemId, interval, attackDate)
        print("Finished kmeans flow field  and entropy calculations")

'''
    Function to get k-means calculations on NetFlow data
    This function only includes the metrics that depend on interval
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
def kmeansMain2(baseFile, systems, start, stop, clusterFrequency, frequency, interval, pathToRawFiles, attackDate):        
    #Kmeans
    for systemId in systems:
        print(str(interval))
        print(systemId)
        silkFile = pathToRawFiles+systemId + "/"+ baseFile
        #entropy
        kmeansEntropyCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
        print("Finished kmeans entropy calculations")
        #combined
        #testingSet = makeDataSetKmeansNetFlow(silkFile, clusterFrequency, systemId, frequency, interval, attackDate)
        #print("Finished with making combined testing data")
        kmeansCombinedCalculation(silkFile, start, stop, clusterFrequency, frequency, systemId, interval, attackDate)
        print("Finished kmeans flow field  and entropy calculations")


#Attack 1
baseFile="twelve-hours-2023-03-08_08-20-sorted.rw"         
systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
start = "2023-03-08 14:15:00"
stop = "2023-03-08 16:00:00"
frequency = timedelta(minutes = 1)
interval = timedelta(minutes = 5)
clusterFrequency = timedelta(minutes = 15)
pathToRawFiles="/data/master-dump/master-thesis/tmp/data/"
attackDate="08.03.23"

kmeansMain(baseFile, systems, start, stop, clusterFrequency, frequency, interval, pathToRawFiles, attackDate)       
interval = timedelta(minutes = 10)
kmeansMain2(baseFile, systems, start, stop, clusterFrequency, frequency, interval, pathToRawFiles, attackDate)        

interval = timedelta(minutes = 15)
clusterFrequency = timedelta(minutes = 30)
kmeansMain2(baseFile, systems, start, stop, clusterFrequency, frequency, interval, pathToRawFiles, attackDate)       
