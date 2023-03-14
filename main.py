from datetime import timedelta
from NetFlow.Entropy.MetricCalculation import metricCalculation
from NetFlow.Entropy.SYNEntropyCalculation import synEntropyCalculation
from NetFlow.Kmeans.CalculationsKmeans import kmeansCalculation
from NetFlow.Kmeans.CalculationsKmeansCombined import kmeansCombinedCalculation
from NetFlow.Kmeans.CalculationsKmeansEntropy import kmeansEntropyCalculation
from NetFlow.Kmeans.MakeTestingDataCombined import makeTestingDataCombined
from NetFlow.RandomForest.CalculationsRandomForest import randomForestCalculations
from NetFlow.RandomForest.MakeDataSet import makeDataSet
from NetFlow.Threshold.ICMPDstUnreachableCalculation import icmpDstUnreachableCalculation
from NetFlow.Threshold.SYNCalculation import synCalculation
def main():
    systems = ["bergen-gw3", "hoytek-gw2", "hovedbygget-gw", "trd-gw", "teknobyen-gw2", "teknobyen-gw1", "ifi2-gw5", 
            "oslo-gw1", "tromso-gw5", "stangnes-gw", "rodbergvn-gw2", "narvik-kv-gw", "narvik-gw3", "tromso-fh-gw",
            "ma2-gw", "narvik-gw4"]
    start = "2023-03-08 08:00:00"
    stop = "2023-03-08 20:00:00"
    frequency = timedelta(minutes = 1)
    interval = timedelta(minutes = 5)
    pathToRawFiles="<PATH TO RAW FILES>/"
    attackDate="08.03"

    for systemId in systems:
        silkFile = pathToRawFiles+systemId + "/twelve-hours-2023-03-08_08-20.rw"
        #Entropy and other metrics calculationS
        metricCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
        #Entropy of SYN calculation
        silkFileSyn = pathToRawFiles+systemId + "/tcp-syn-twelve-hours-2023-03-08_08-20.rw"
        synEntropyCalculation(silkFileSyn, start, stop, systemId,  frequency, interval, attackDate)
        #ICMP unreachable calculation
        silkFileICMP3 = pathToRawFiles+systemId + "/icmp3-twelve-hours-2023-03-08_08-20.rw"
        icmpDstUnreachableCalculation(silkFileICMP3, start, stop, systemId, frequency, attackDate)
        #SYN calculation
        synCalculation(silkFileSyn, start, stop, systemId, attackDate)
        #Kmeans
        #normal
        kmeansCalculation(silkFile, systemId, attackDate)
        #entropy
        kmeansEntropyCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
        #combined
        makeTestingDataCombined(systemId, attackDate)
        kmeansCombinedCalculation(systemId, attackDate)
        #RandomForest
        startRFTraining = "2023-03-08 10:00:00"
        stopRFTraining = "2023-03-08 15:00:00"
        trainingSet = makeDataSet(silkFile, startRFTraining, stopRFTraining, systemId, frequency, interval, "Training", attackDate)
        trainingSet.to_pickle("NetFlow/RandomForest/RawData/TrainingSet."+str(systemId)+ ".pkl")
        startRFTesting = "2023-03-08 15:00:00"
        stopRFTesting = "2023-03-08 16:00:00"
        testingSet = makeDataSet(silkFile, startRFTesting, stopRFTesting, systemId, frequency, interval, "Testing", attackDate)
        testingSet.to_pickle("NetFlow/RandomForest/RawData/TestingSet."+str(systemId)+ ".pkl")
        randomForestCalculations(systemId, attackDate)
#main()

def main2():
    systems = ["oslo-gw"]
    start = "2011-01-01 08:00:00"
    stop = "2011-01-01 20:00:00"
    frequency = timedelta(minutes = 1)
    interval = timedelta(minutes = 5)
    pathToRawFiles="/home/linneafg/silk-data/RawDataFromFilter/"
    attackDate="01.01"

    for systemId in systems:
        silkFile = pathToRawFiles+systemId + "/twelve-hours-2011-01-01_08-20-sorted.rw"
        #Entropy and other metrics calculations
        metricCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
        print("Finished entropy and other metrics calculations")
        #Entropy of SYN calculation
        silkFileSyn = pathToRawFiles+systemId + "/tcp-syn-twelve-hours-2011-01-01_08-20-sorted.rw"
        synEntropyCalculation(silkFileSyn, start, stop, systemId,  frequency, interval, attackDate)
        print("Finished entropy of SYN calculation")
        #ICMP unreachable calculation
        silkFileICMP3 = pathToRawFiles+systemId + "/icmp3-twelve-hours-2011-01-01_08-20-sorted.rw"
        icmpDstUnreachableCalculation(silkFileICMP3, start, stop, systemId, frequency, attackDate)
        print("Finished icmp unreachable calculations")
        #SYN calculation
        synCalculation(silkFileSyn, start, stop, systemId, attackDate)
        print("Finished SYN calculations")
        #Kmeans
        #normal
        kmeansCalculation(silkFile, systemId, attackDate)
        print("Finished kmeans flow field calculations")
        #entropy
        kmeansEntropyCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
        print("Finished kmeans entropy calculations")
        #combined
        makeTestingDataCombined(systemId, attackDate)
        kmeansCombinedCalculation(systemId, attackDate)
        print("Finished kmeans flow field  and entropy calculations")
        #RandomForest
        startRFTraining = "2011-01-01 10:00:00"
        stopRFTraining = "2011-01-01 15:00:00"
        trainingSet = makeDataSet(silkFile, startRFTraining, stopRFTraining, systemId, frequency, interval, "Training", attackDate)
        trainingSet.to_pickle("NetFlow/RandomForest/RawData/TrainingSet.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
        startRFTesting = "2011-01-01 15:00:00"
        stopRFTesting = "2011-01-01 16:00:00"
        testingSet = makeDataSet(silkFile, startRFTesting, stopRFTesting, systemId, frequency, interval, "Testing", attackDate)
        testingSet.to_pickle("NetFlow/RandomForest/RawData/TestingSet.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
        randomForestCalculations(systemId, attackDate)
        print("Finished Random Forest calculations")
main2()