from datetime import timedelta
import os
from NetFlow.Entropy.FindAttackFlows import findAttackFlows
from NetFlow.Entropy.FindAttackFlowsSYN import findAttackFlowsSYN
from NetFlow.Entropy.MetricCalculation import metricCalculation
from NetFlow.Entropy.SYNEntropyCalculation import synEntropyCalculation
from NetFlow.RandomForest.CalculationsRandomForest import calculationsRandomForestNetFlow, calculationsRandomForestNoIPNetFlow
from NetFlow.RandomForest.CalculationsRandomForestEntropy import calculationRandomForestNetFlowEntropy
from NetFlow.RandomForest.CalculationsRandomForestFields import calculationRandomForestNetFlowFields, calculationRandomForestNoIPNetFlowFields
from NetFlow.RandomForest.MakeDataSet import makeDataSetNetFlow
from NetFlow.RandomForest.MakeDataSetEntropy import makeDataSetNetFlowEntropy
from NetFlow.RandomForest.MakeDataSetFields import makeDataSetNetFlowFields
from NetFlow.RandomForest.MakeTestingDataSet import makeTestingDataSetNetFlow
from NetFlow.RandomForest.MakeTestingDataSetFields import makeTestingDataSetNetFlowFields
from NetFlow.RandomForest.TrainFields import trainFields
from NetFlow.Threshold.FindAttackFlowsICMPDstUnreachable import findAttackFlowsICMPdstUnreachable
from NetFlow.Threshold.ICMPDstUnreachableCalculation import icmpDstUnreachableCalculation
from NetFlow.Threshold.SYNCalculation import synCalculation
from NetFlow.Threshold.XmasCalculation import xmasCalculation
from NetFlow.TopKFlows.topkflowCalculation import topkflows2

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
        print(systemId)
        print(str(interval))
        silkFile = pathToRawFiles+systemId + "/"+ baseFile
        #Entropy and other metrics calculations
        findAttackFlows(silkFile, start, stop, systemId, frequency, interval, attackDate)
        print("Finished entropy and other metrics calculations")
        #Entropy of SYN calculation
        silkFileSyn = pathToRawFiles+systemId + "/tcp-syn-"+ baseFile
        findAttackFlowsSYN(silkFileSyn, start, stop, systemId, frequency, interval, attackDate)
        print("Finished entropy of SYN calculation")
        #ICMP unreachable calculation
        silkFileICMP3 = pathToRawFiles+systemId + "/icmp3-"+ baseFile
        findAttackFlowsICMPdstUnreachable(silkFileICMP3, start, stop, systemId, frequency, interval, attackDate)
        print("Finished icmp unreachable calculations")
        #SYN calculation
        synCalculation(silkFileSyn, start, stop, systemId, attackDate)
        print("Finished SYN calculations")
        #TopKflows
        topkflows2(silkFile, start, stop, frequency, 20, attackDate, systemId)
        print("Finished top k flows")
        xmasCalculation(silkFile, start, stop, systemId, attackDate)
        print("Finished Xmas calculation")

def randomForestMain(trainingBase, testingBase, estimator, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequency, intervals, systems, pathToRawFiles, attackDate):
    for systemId in systems:
        print(systemId)
        trainingFile = pathToRawFiles+systemId + "/"+ trainingBase
        testingFile = pathToRawFiles+systemId + "/"+ testingBase

        makeDataSetNetFlowFields(trainingFile, startRFTraining, stopRFTraining, "Training", systemId, attackDate)
        makeTestingDataSetNetFlowFields(testingFile, startRFTesting, stopRFTesting, "Testing", systemId, attackDate)
        trainFields(systemId, attackDate, estimator)
        calculationRandomForestNetFlowFields(systemId, attackDate, estimator)
        print("Finished Random Forest calculations on fields")

        calculationRandomForestNoIPNetFlowFields(systemId, attackDate, estimator)
        print("Finished Random Forest calculations on fields without IPs")

        for interval in intervals:
            print(interval)
            makeDataSetNetFlowEntropy(trainingFile, startRFTraining, stopRFTraining, frequency, interval, "Training", systemId, attackDate)
            makeDataSetNetFlowEntropy(testingFile, startRFTesting, stopRFTesting, frequency, interval, "Testing", systemId, attackDate)
            calculationRandomForestNetFlowEntropy(systemId, interval, attackDate, estimator)
            print("Finished Random Forest calculations on entropy")

            makeDataSetNetFlow(trainingFile, startRFTraining, stopRFTraining, frequency, interval, "Training", systemId, attackDate)
            makeTestingDataSetNetFlow(testingFile, startRFTesting, stopRFTesting, frequency, interval, "Testing", systemId, attackDate)
            calculationsRandomForestNetFlow(systemId, interval, attackDate, estimator)
            print("Finished Random Forest calculations on all fields")

            calculationsRandomForestNoIPNetFlow(systemId, interval, attackDate, estimator)
            print("Finished Random Forest calculations without IPs")

            if os.path.exists("NetFlow/RandomForest/DataSets/Training/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"):
                os.remove("NetFlow/RandomForest/DataSets/Training/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy")
            else:
                print("The file NetFlow/RandomForest/DataSets/Training/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy does not exist") 

            if os.path.exists("NetFlow/RandomForest/DataSets/Testing/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"):
                os.remove("NetFlow/RandomForest/DataSets/Testing/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy")
            else:
                print("The file NetFlow/RandomForest/DataSets/Testing/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy does not exist") 

            if os.path.exists("NetFlow/RandomForest/DataSets/Training/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"):
                os.remove("NetFlow/RandomForest/DataSets/Training/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy")
            else:
                print("The file NetFlow/RandomForest/DataSets/Training/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy does not exist") 

            for i in range(1,9):
                if os.path.exists("NetFlow/RandomForest/DataSets/Testing/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+"."+ str(i) + ".npy"):
                    os.remove("NetFlow/RandomForest/DataSets/Testing/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+"."+ str(i) + ".npy")
                else:
                    print("The file NetFlow/RandomForest/DataSets/Testing/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+"."+ str(i) + ".npy does not exist") 
        if os.path.exists("NetFlow/RandomForest/DataSets/Training/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"):
            os.remove("NetFlow/RandomForest/DataSets/Training/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".npy")
        else:
            print("The file NetFlow/RandomForest/DataSets/Training/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".npy does not exist") 

        for i in range(1,9):
            if os.path.exists("NetFlow/RandomForest/DataSets/Testing/Fields.attack."+str(attackDate)+ "."+str(systemId)+"."+ str(i) + ".npy"):
                os.remove("NetFlow/RandomForest/DataSets/Testing/Fields.attack."+str(attackDate)+ "."+str(systemId)+"."+ str(i) + ".npy")
            else:
                print("The file NetFlow/RandomForest/DataSets/Testing/Fields.attack."+str(attackDate)+ "."+str(systemId)+"."+ str(i) + ".npy does not exist") 

#Attack number 2
baseFile="2023-03-17_11-14-sorted.rw"         
systems = ["tromso-gw5",  "teknobyen-gw1","hoytek-gw2", "bergen-gw3", "trd-gw", "ifi2-gw5"]
start = "2023-03-17 11:00:00"
stop = "2023-03-17 14:00:00"

frequency = timedelta(minutes = 1)
interval = timedelta(minutes = 5)
pathToRawFiles="/data/master-dump/fresh-netflow-data/master-dump/"
attackDate="17.03.23"

main(baseFile, systems, start, stop, frequency, interval, pathToRawFiles, attackDate)    


#Attack number 3
baseFile="2023-03-24_14-18-sorted.rw"         
systems = ["tromso-gw5",  "teknobyen-gw1","hoytek-gw2", "bergen-gw3", "trd-gw", "ifi2-gw5"]
start = "2023-03-24 14:00:00"
stop = "2023-03-24 18:00:00"
frequency = timedelta(minutes = 1)
interval = timedelta(minutes = 5)
intervals = [timedelta(minutes = 5), timedelta(minutes = 10), timedelta(minutes = 15)]
pathToRawFiles="/data/master-dump/fresh-netflow-data/master-dump/"
attackDate="24.03.23"

main(baseFile, systems, start, stop, frequency, interval, pathToRawFiles, attackDate)       

estimator = 100
trainingBase="2023-03-17_11-14-sorted.rw" 
testingBase="2023-03-24_14-18-sorted.rw" 

startRFTraining = "2023-03-17 11:00:00"
stopRFTraining = "2023-03-17 13:00:00"
startRFTesting = "2023-03-24 14:00:00"
stopRFTesting = "2023-03-24 18:00:00"
randomForestMain(trainingBase, testingBase, estimator, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequency, intervals, systems, pathToRawFiles, attackDate)