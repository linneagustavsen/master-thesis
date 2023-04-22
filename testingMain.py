from datetime import timedelta
from NetFlow.Entropy.MetricCalculation import metricCalculation
from NetFlow.Entropy.SYNEntropyCalculation import synEntropyCalculation
from NetFlow.Kmeans.CalculationsKmeans import kmeansCalculation
from NetFlow.Kmeans.CalculationsKmeansCombined import kmeansCombinedCalculation
from NetFlow.Kmeans.CalculationsKmeansEntropy import kmeansEntropyCalculation
from NetFlow.Kmeans.MakeDataSet import makeDataSetKmeansNetFlow
from NetFlow.RandomForest.CalculationsRandomForest import calculationsRandomForestNetFlow, calculationsRandomForestNoIPNetFlow
from NetFlow.RandomForest.CalculationsRandomForestEntropy import calculationRandomForestNetFlowEntropy
from NetFlow.RandomForest.CalculationsRandomForestFields import calculationRandomForestNetFlowFields, calculationRandomForestNoIPNetFlowFields
from NetFlow.RandomForest.MakeDataSet import makeDataSetNetFlow, makeDataSetNoIPNetFlow
from NetFlow.RandomForest.MakeDataSetEntropy import makeDataSetNetFlowEntropy
from NetFlow.RandomForest.MakeDataSetFields import makeDataSetNetFlowFields, makeDataSetNoIPNetFlowFields
from NetFlow.Threshold.ICMPDstUnreachableCalculation import icmpDstUnreachableCalculation
from NetFlow.Threshold.SYNCalculation import synCalculation
from NetFlow.TopKFlows.topkflow import topkflows2

'''
    Function to get different calculations on NetFlow data
    Input:  baseFile:       string, raw base file with SiLK NetFlow records,
            systems:        list of strings, list of systems the calculations will be made on,
            start:          string, indicates the start time of the records,
            stop:           string, indicates the stop time of the records,
            frequency:      timedelta object, frequency of metric calculation,
            interval:       timedelta object, size of the sliding window which the calculation is made on,
            pathToRawFiles: string, path to the SiLK NetFlow records,
            attackDate:     string, date of the attack the calculations are made on
'''
def main(baseFile, systems, start, stop, frequency, interval, pathToRawFiles, attackDate):
    for systemId in systems:
        silkFile = pathToRawFiles+systemId + "/"+ baseFile
        #Entropy and other metrics calculations
        metricCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
        print("Finished entropy and other metrics calculations")
        #Entropy of SYN calculation
        silkFileSyn = pathToRawFiles+systemId + "/tcp-syn-"+ baseFile
        synEntropyCalculation(silkFileSyn, start, stop, systemId, frequency, interval, attackDate)
        print("Finished entropy of SYN calculation")
        #ICMP unreachable calculation
        silkFileICMP3 = pathToRawFiles+systemId + "/icmp3-"+ baseFile
        icmpDstUnreachableCalculation(silkFileICMP3, start, stop, systemId, frequency, interval, attackDate)
        print("Finished icmp unreachable calculations")
        #SYN calculation
        synCalculation(silkFileSyn, start, stop, systemId, attackDate)
        print("Finished SYN calculations")
        #TopKflows
        topkflows2(silkFile, start, stop, frequency, 20, attackDate, systemId)
        print("Finished top k flows")

'''
    Function to get different calculations on NetFlow data
    This function only includes the metrics that depend on interval
    Input:  baseFile:       string, raw base file with SiLK NetFlow records,
            systems:        list of strings, systems the calculations will be made on,
            start:          string, indicates the start time of the records,
            stop:           string, indicates the stop time of the records,
            frequency:      timedelta object, frequency of metric calculation,
            interval:       timedelta object, size of the sliding window which the calculation is made on,
            pathToRawFiles: string, path to the SiLK NetFlow records,
            attackDate:     string, date of the attack the calculations are made on
'''
def main2(baseFile, systems, start, stop, frequency, interval, pathToRawFiles, attackDate):
    for systemId in systems:
        silkFile = pathToRawFiles+systemId + "/"+ baseFile
        #Entropy and other metrics calculations
        metricCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
        print("Finished entropy and other metrics calculations")
        #Entropy of SYN calculation
        silkFileSyn = pathToRawFiles+systemId + "/tcp-syn-"+ baseFile
        synEntropyCalculation(silkFileSyn, start, stop, systemId, frequency, interval, attackDate)
        print("Finished entropy of SYN calculation")
        silkFileICMP3 = pathToRawFiles+systemId + "/icmp3-"+ baseFile
        icmpDstUnreachableCalculation(silkFileICMP3, start, stop, systemId, frequency, interval, attackDate)
        print("Finished icmp unreachable calculations")

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
def kmeansMain(baseFile, systems, start, stop, startCombined, stopCombined, frequency, interval, pathToRawFiles, attackDate):        
    #Kmeans
    for systemId in systems:
        silkFile = pathToRawFiles+systemId + "/"+ baseFile
        #normal
        #kmeansCalculation(silkFile, start, stop, systemId, attackDate)
        print("Finished kmeans flow field calculations")
        #entropy
        #kmeansEntropyCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
        print("Finished kmeans entropy calculations")
        #combined
        testingSet = makeDataSetKmeansNetFlow(silkFile, startCombined, stopCombined, systemId, frequency, interval, attackDate)
        print("Finished with making combined testing data")
        kmeansCombinedCalculation(testingSet, systemId, interval, attackDate)
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
def kmeansMain2(baseFile, systems, start, stop, startCombined, stopCombined, frequency, interval, pathToRawFiles, attackDate):        
    #Kmeans
    for systemId in systems:
        silkFile = pathToRawFiles+systemId + "/"+ baseFile
        #entropy
        kmeansEntropyCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate)
        print("Finished kmeans entropy calculations")
        #combined
        testingSet = makeDataSetKmeansNetFlow(silkFile, startCombined, stopCombined, systemId, frequency, interval, attackDate)
        print("Finished with making combined testing data")
        kmeansCombinedCalculation(testingSet, systemId, interval, attackDate)
        print("Finished kmeans flow field  and entropy calculations")


'''
    Function to do Random Forest classifier on NetFlow data
    Input:  trainingBase:   string, raw base file with SiLK NetFlow records for the training data,
            testingBase:    string, raw base file with SiLK NetFlow records for the testing data,
            systems:        list of strings, systems the calculations will be made on,
            startRFTraining:string, indicates the start time of the training records,
            stopRFTraining: string, indicates the stop time of the training records,
            startRFTesting: string, indicates the start time of the testing records,
            stopRFTesting:  string, indicates the stop time of the testing records,
            frequency:      timedelta object, frequency of metric calculation,
            interval:       timedelta object, size of the sliding window which the calculation is made on,
            pathToRawFiles: string, path to the SiLK NetFlow records,
            attackDate:     string, date of the attack the calculations are made on
'''       
def randomForestMain(trainingBase, testingBase, systems, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequency, interval, pathToRawFiles, attackDate):
    for systemId in systems:
        trainingFile = pathToRawFiles+systemId + "/"+ trainingBase
        testingFile = pathToRawFiles+systemId + "/"+ testingBase
        
        #trainingSet = makeDataSetNetFlow(trainingFile, startRFTraining, stopRFTraining, systemId, frequency, interval, "Training", attackDate)        
        #testingSet = makeDataSetNetFlow(testingFile, startRFTesting, stopRFTesting, systemId, frequency, interval, "Testing", attackDate)
        #calculationsRandomForestNetFlow(trainingSet, testingSet, systemId, interval, attackDate)
        print("Finished Random Forest calculations on all fields")

        #trainingSet = makeDataSetNoIPNetFlow(trainingFile, startRFTraining, stopRFTraining, systemId, frequency, interval, "Training", attackDate)
        #testingSet = makeDataSetNoIPNetFlow(testingFile, startRFTesting, stopRFTesting, systemId, frequency, interval, "Testing", attackDate)
        #calculationsRandomForestNoIPNetFlow(trainingSet, testingSet, systemId, interval, attackDate)
        print("Finished Random Forest calculations without IPs")

        #trainingSet = makeDataSetNetFlowEntropy(trainingFile, startRFTraining, stopRFTraining, systemId, frequency, interval, "Training", attackDate)
        #testingSet = makeDataSetNetFlowEntropy(testingFile, startRFTesting, stopRFTesting, systemId, frequency, interval, "Testing", attackDate)
        #calculationRandomForestNetFlowEntropy(trainingSet, testingSet, systemId, interval, frequency, attackDate)
        print("Finished Random Forest calculations on entropy")

        #trainingSet = makeDataSetNetFlowFields(trainingFile, startRFTraining, stopRFTraining, systemId, "Training", attackDate)
        #testingSet = makeDataSetNetFlowFields(testingFile, startRFTesting, stopRFTesting, systemId, "Testing", attackDate)
        #calculationRandomForestNetFlowFields(trainingSet, testingSet, systemId, attackDate)
        print("Finished Random Forest calculations on fields")

        trainingSet = makeDataSetNoIPNetFlowFields(trainingFile, startRFTraining, stopRFTraining, systemId, "Training", attackDate)
        testingSet = makeDataSetNoIPNetFlowFields(testingFile, startRFTesting, stopRFTesting, systemId, "Testing", attackDate)
        calculationRandomForestNoIPNetFlowFields(trainingSet, testingSet, systemId, attackDate)
        print("Finished Random Forest calculations on fields without IPs")

'''
    Function to do Random Forest classifier on NetFlow data
    This function only includes the metrics that depend on interval
    Input:  trainingBase:   string, raw base file with SiLK NetFlow records for the training data,
            testingBase:    string, raw base file with SiLK NetFlow records for the testing data,
            systems:        list of strings, systems the calculations will be made on,
            startRFTraining:string, indicates the start time of the training records,
            stopRFTraining: string, indicates the stop time of the training records,
            startRFTesting: string, indicates the start time of the testing records,
            stopRFTesting:  string, indicates the stop time of the testing records,
            frequency:      timedelta object, frequency of metric calculation,
            interval:       timedelta object, size of the sliding window which the calculation is made on,
            pathToRawFiles: string, path to the SiLK NetFlow records,
            attackDate:     string, date of the attack the calculations are made on
'''  
def randomForestMain2(trainingBase, testingBase, systems, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequency, interval, pathToRawFiles, attackDate):
    for systemId in systems:
        trainingFile = pathToRawFiles+systemId + "/"+ trainingBase
        testingFile = pathToRawFiles+systemId + "/"+ testingBase
        
        trainingSet = makeDataSetNetFlow(trainingFile, startRFTraining, stopRFTraining, systemId, frequency, interval, "Training", attackDate)        
        testingSet = makeDataSetNetFlow(testingFile, startRFTesting, stopRFTesting, systemId, frequency, interval, "Testing", attackDate)
        calculationsRandomForestNetFlow(trainingSet, testingSet, systemId, interval, attackDate)
        print("Finished Random Forest calculations on all fields")

        trainingSet = makeDataSetNoIPNetFlow(trainingFile, startRFTraining, stopRFTraining, systemId, frequency, interval, "Training", attackDate)
        testingSet = makeDataSetNoIPNetFlow(testingFile, startRFTesting, stopRFTesting, systemId, frequency, interval, "Testing", attackDate)
        calculationsRandomForestNoIPNetFlow(trainingSet, testingSet, systemId, interval, attackDate)
        print("Finished Random Forest calculations without IPs")

        trainingSet = makeDataSetNetFlowEntropy(trainingFile, startRFTraining, stopRFTraining, systemId, frequency, interval, "Training", attackDate)
        testingSet = makeDataSetNetFlowEntropy(testingFile, startRFTesting, stopRFTesting, systemId, frequency, interval, "Testing", attackDate)
        calculationRandomForestNetFlowEntropy(trainingSet, testingSet, systemId, interval, frequency, attackDate)
        print("Finished Random Forest calculations on entropy")

#Attack 1
baseFile="two-hours-2011-02-08_10-12-sorted.rw"         
systems = ["oslo-gw"]
start = "2011-02-08 10:00:00"
stop = "2011-02-08 12:00:00"
startCombined = "2011-02-08 10:00:00"
stopCombined = "2011-02-08 12:00:00"
frequency = timedelta(minutes = 1)
interval = timedelta(minutes = 5)
pathToRawFiles="/home/linneafg/silk-data/RawDataFromFilter/"
attackDate="08.02.11"

main(baseFile, systems, start, stop, frequency, interval, pathToRawFiles, attackDate)
kmeansMain(baseFile, systems, start, stop, startCombined, stopCombined, frequency, interval, pathToRawFiles, attackDate)        

trainingBase="two-hours-2011-02-08_10-12-sorted.rw"
testingBase="two-hours-2011-02-08_10-12-sorted.rw"
startRFTraining = "2011-02-08 10:00:00"
stopRFTraining = "2011-02-08 11:00:00"
startRFTesting = "2011-02-08 11:00:00"
stopRFTesting = "2011-02-08 12:00:00"
#randomForestMain(trainingBase, testingBase, systems, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequency, interval, pathToRawFiles, attackDate)

interval = timedelta(minutes = 10)
main2(baseFile, systems, start, stop, frequency, interval, pathToRawFiles, attackDate)
kmeansMain2(baseFile, systems, start, stop, startCombined, stopCombined, frequency, interval, pathToRawFiles, attackDate)        
randomForestMain2(trainingBase, testingBase, systems, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequency, interval, pathToRawFiles, attackDate)

interval = timedelta(minutes = 15)
main2(baseFile, systems, start, stop, startCombined, stopCombined, frequency, interval, pathToRawFiles, attackDate)
kmeansMain2(baseFile, systems, start, stop, startCombined, stopCombined, frequency, interval, pathToRawFiles, attackDate)        
randomForestMain2(trainingBase, testingBase, systems, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequency, interval, pathToRawFiles, attackDate)