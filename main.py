from datetime import timedelta
from NetFlow.Entropy.MetricCalculation import metricCalculation
from NetFlow.Entropy.SYNEntropyCalculation import synEntropyCalculation
from NetFlow.Kmeans.CalculationsKmeans import kmeansCalculation
from NetFlow.Kmeans.CalculationsKmeansCombined import kmeansCombinedCalculation
from NetFlow.Kmeans.CalculationsKmeansEntropy import kmeansEntropyCalculation
from NetFlow.Kmeans.MakeTestingDataCombined import makeTestingDataCombined
from NetFlow.RandomForest.CalculationsRandomForest import *
from NetFlow.RandomForest.MakeDataSet import *
from NetFlow.Threshold.ICMPDstUnreachableCalculation import icmpDstUnreachableCalculation
from NetFlow.Threshold.SYNCalculation import synCalculation

def main(baseFile, systems, start, stop, startCombined, stopCombined, frequency, interval, pathToRawFiles, attackDate):
    for systemId in systems:
        silkFile = pathToRawFiles+systemId + "/"+ baseFile
        #Entropy and other metrics calculations
        metricCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
        print("Finished entropy and other metrics calculations")
        #Entropy of SYN calculation
        silkFileSyn = pathToRawFiles+systemId + "/tcp-syn-"+ baseFile
        synEntropyCalculation(silkFileSyn, start, stop, systemId,  frequency, interval, attackDate)
        print("Finished entropy of SYN calculation")
        #ICMP unreachable calculation
        silkFileICMP3 = pathToRawFiles+systemId + "/icmp3-"+ baseFile
        icmpDstUnreachableCalculation(silkFileICMP3, start, stop, systemId, frequency, attackDate)
        print("Finished icmp unreachable calculations")
        #SYN calculation
        synCalculation(silkFileSyn, start, stop, systemId, attackDate)
        print("Finished SYN calculations")
        #Kmeans
        #normal
        kmeansCalculation(silkFile, start, stop, systemId, attackDate)
        print("Finished kmeans flow field calculations")
        #entropy
        kmeansEntropyCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
        print("Finished kmeans entropy calculations")
        #combined
        makeTestingDataCombined(silkFile, startCombined, stopCombined, systemId, frequency, interval, attackDate)
        print("Finished with making combined testing data")
        kmeansCombinedCalculation(systemId, interval, attackDate)
        print("Finished kmeans flow field  and entropy calculations")

def main2(baseFile, systems, start, stop, startCombined, stopCombined, frequency, interval, pathToRawFiles, attackDate):
    for systemId in systems:
        silkFile = pathToRawFiles+systemId + "/"+ baseFile
        #Entropy and other metrics calculations
        metricCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
        print("Finished entropy and other metrics calculations")
        #Entropy of SYN calculation
        silkFileSyn = pathToRawFiles+systemId + "/tcp-syn-"+ baseFile
        synEntropyCalculation(silkFileSyn, start, stop, systemId,  frequency, interval, attackDate)
        print("Finished entropy of SYN calculation")

        #entropy
        kmeansEntropyCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
        print("Finished kmeans entropy calculations")
        #combined
        makeTestingDataCombined(silkFile, startCombined, stopCombined, systemId, frequency, interval, attackDate)
        print("Finished with making combined testing data")
        kmeansCombinedCalculation(systemId, interval, attackDate)
        print("Finished kmeans flow field  and entropy calculations")
        
def randomForestMain(trainingBase, testingBase, systems, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequency, interval, pathToRawFiles, attackDate):
    for systemId in systems:
        trainingFile = pathToRawFiles+systemId + "/"+ trainingBase
        testingFile = pathToRawFiles+systemId + "/"+ testingBase
        
        trainingSet = makeDataSet(trainingFile, startRFTraining, stopRFTraining, systemId, frequency, interval, "Training", attackDate)
        #trainingSet.to_pickle("NetFlow/RandomForest/RawData/TrainingSet."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")

        testingSet = makeDataSet(testingFile, startRFTesting, stopRFTesting, systemId, frequency, interval, "Testing", attackDate)
        #testingSet.to_pickle("NetFlow/RandomForest/RawData/TestingSet."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
        randomForestCalculations(trainingSet, testingSet, systemId, interval, attackDate)
        print("Finished Random Forest calculations on all fields")

        trainingSet = makeDataSetNoIP(trainingFile, startRFTraining, stopRFTraining, systemId, frequency, interval, "Training", attackDate)
        #trainingSet.to_pickle("NetFlow/RandomForest/RawData/TrainingSet."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")

        testingSet = makeDataSetNoIP(testingFile, startRFTesting, stopRFTesting, systemId, frequency, interval, "Testing", attackDate)
        #testingSet.to_pickle("NetFlow/RandomForest/RawData/TestingSet."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
        randomForestCalculationsNoIP(trainingSet, testingSet, systemId, interval, attackDate)
        print("Finished Random Forest calculations without IPs")

#Attack 1
baseFile="twelve-hours-2023-03-08_08-20-sorted.rw"         
systems = ["bergen-gw3", "hoytek-gw2", "hovedbygget-gw", "trd-gw", "teknobyen-gw2", "teknobyen-gw1", "ifi2-gw5", 
            "oslo-gw1", "tromso-gw5", "stangnes-gw", "rodbergvn-gw2", "narvik-kv-gw", "narvik-gw3", "tromso-fh-gw",
            "ma2-gw", "narvik-gw4"]
start = "2023-03-08 08:00:00"
stop = "2023-03-08 20:00:00"
startCombined = "2023-03-08 10:00:00"
stopCombined = "2023-03-08 16:00:00"
frequency = timedelta(minutes = 1)
interval = timedelta(minutes = 5)
pathToRawFiles="<PATH TO RAW FILES>/"
attackDate="08.03"

main(baseFile, systems, start, stop, startCombined, stopCombined, frequency, interval, pathToRawFiles, attackDate)

trainingBase="twelve-hours-2023-03-08_08-20-sorted.rw"
testingBase="twelve-hours-2023-03-08_08-20-sorted.rw"
startRFTraining = "2023-03-08 10:00:00"
stopRFTraining = "2023-03-08 15:00:00"
startRFTesting = "2023-03-08 15:00:00"
stopRFTesting = "2023-03-08 16:00:00"
randomForestMain(trainingBase, testingBase, systems, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequency, interval, attackDate)

interval = timedelta(minutes = 10)
main2(baseFile, systems, start, stop, startCombined, stopCombined, frequency, interval, pathToRawFiles, attackDate)
randomForestMain(trainingBase, testingBase, systems, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequency, interval, pathToRawFiles, attackDate)

interval = timedelta(minutes = 15)
main2(baseFile, systems, start, stop, startCombined, stopCombined, frequency, interval, pathToRawFiles, attackDate)
randomForestMain(trainingBase, testingBase, systems, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequency, interval, pathToRawFiles, attackDate)


#Attack number 2
baseFile="twelve-hours-2023-03-17_08-20-sorted.rw"         
systems = ["bergen-gw3", "hoytek-gw2", "hovedbygget-gw", "trd-gw", "teknobyen-gw2", "teknobyen-gw1", "ifi2-gw5", 
            "oslo-gw1", "tromso-gw5", "stangnes-gw", "rodbergvn-gw2", "narvik-kv-gw", "narvik-gw3", "tromso-fh-gw",
            "ma2-gw", "narvik-gw4"]
start = "2023-03-17 08:00:00"
stop = "2023-03-17 20:00:00"
startCombined = "2023-03-17 10:00:00"
stopCombined = "2023-03-17 16:00:00"
frequency = timedelta(minutes = 1)
interval = timedelta(minutes = 5)
pathToRawFiles="<PATH TO RAW FILES>/"
attackDate="17.03"

main(baseFile, systems, start, stop, startCombined, stopCombined, frequency, interval, pathToRawFiles, attackDate)

trainingBase="twelve-hours-2023-03-17_08-20-sorted.rw"
testingBase="twelve-hours-2023-03-24_08-20-sorted.rw"
startRFTraining = "2023-03-17 12:00:00"
stopRFTraining = "2023-03-17 14:00:00"
startRFTesting = "2023-03-24 14:30:00"
stopRFTesting = "2023-03-24 19:00:00"
randomForestMain(trainingBase, testingBase, systems, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequency, interval, attackDate)

interval = timedelta(minutes = 10)
main2(baseFile, systems, start, stop, startCombined, stopCombined, frequency, interval, pathToRawFiles, attackDate)
randomForestMain(trainingBase, testingBase, systems, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequency, interval, pathToRawFiles, attackDate)

interval = timedelta(minutes = 15)
main2(baseFile, systems, start, stop, startCombined, stopCombined, frequency, interval, pathToRawFiles, attackDate)
randomForestMain(trainingBase, testingBase, systems, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequency, interval, pathToRawFiles, attackDate)

#Attack number 3
baseFile="twelve-hours-2023-03-24_08-20-sorted.rw"         
systems = ["bergen-gw3", "hoytek-gw2", "hovedbygget-gw", "trd-gw", "teknobyen-gw2", "teknobyen-gw1", "ifi2-gw5", 
            "oslo-gw1", "tromso-gw5", "stangnes-gw", "rodbergvn-gw2", "narvik-kv-gw", "narvik-gw3", "tromso-fh-gw",
            "ma2-gw", "narvik-gw4"]
start = "2023-03-24 08:00:00"
stop = "2023-03-24 20:00:00"
startCombined = "2023-03-24 14:00:00"
stopCombined = "2023-03-24 19:00:00"
frequency = timedelta(minutes = 1)
interval = timedelta(minutes = 5)
pathToRawFiles="<PATH TO RAW FILES>/"
attackDate="24.03"

main(baseFile, systems, start, stop, startCombined, stopCombined, frequency, interval, pathToRawFiles, attackDate)

interval = timedelta(minutes = 10)
main2(baseFile, systems, start, stop, startCombined, stopCombined, frequency, interval, pathToRawFiles, attackDate)

interval = timedelta(minutes = 15)
main2(baseFile, systems, start, stop, startCombined, stopCombined, frequency, interval, pathToRawFiles, attackDate)