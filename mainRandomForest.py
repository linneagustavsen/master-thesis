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
from datetime import timedelta
from NetFlow.RandomForest.CalculationsRandomForest import calculationsRandomForestNetFlow, calculationsRandomForestNoIPNetFlow
from NetFlow.RandomForest.CalculationsRandomForestEntropy import calculationRandomForestNetFlowEntropy
from NetFlow.RandomForest.CalculationsRandomForestFields import calculationRandomForestNetFlowFields, calculationRandomForestNoIPNetFlowFields
from NetFlow.RandomForest.MakeDataSet import makeDataSetNetFlow, makeDataSetNoIPNetFlow
from NetFlow.RandomForest.MakeDataSetEntropy import makeDataSetNetFlowEntropy
from NetFlow.RandomForest.MakeDataSetFields import makeDataSetNetFlowFields, makeDataSetNoIPNetFlowFields
import numpy as np

def randomForestMain(trainingBase, testingBase, systems, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequency, interval, pathToRawFiles, attackDate):
    for systemId in systems:
        trainingFile = pathToRawFiles+systemId + "/"+ trainingBase
        testingFile = pathToRawFiles+systemId + "/"+ testingBase

        '''makeDataSetNetFlowFields(trainingFile, startRFTraining, stopRFTraining, "Training", systemId, attackDate)
        makeDataSetNetFlowFields(testingFile, startRFTesting, stopRFTesting, "Testing", systemId, attackDate)
        calculationRandomForestNetFlowFields(systemId, attackDate)
        print("Finished Random Forest calculations on fields")

        makeDataSetNoIPNetFlowFields(trainingFile, startRFTraining, stopRFTraining, "Training", systemId, attackDate)
        makeDataSetNoIPNetFlowFields(testingFile, startRFTesting, stopRFTesting, "Testing", systemId, attackDate)
        calculationRandomForestNoIPNetFlowFields(systemId, attackDate)
        print("Finished Random Forest calculations on fields without IPs")

        makeDataSetNetFlowEntropy(trainingFile, startRFTraining, stopRFTraining, frequency, interval, "Training", systemId, attackDate)
        makeDataSetNetFlowEntropy(testingFile, startRFTesting, stopRFTesting, frequency, interval, "Testing", systemId, attackDate)
        calculationRandomForestNetFlowEntropy(systemId, interval, attackDate)
        print("Finished Random Forest calculations on entropy")

        makeDataSetNetFlow(trainingFile, startRFTraining, stopRFTraining, frequency, interval, "Training", systemId, attackDate)
        makeDataSetNetFlow(testingFile, startRFTesting, stopRFTesting, frequency, interval, "Testing", systemId, attackDate)
        calculationsRandomForestNetFlow(systemId, interval, attackDate)
        print("Finished Random Forest calculations on all fields")'''

        makeDataSetNoIPNetFlow(trainingFile, startRFTraining, stopRFTraining, frequency, interval, "Training", systemId, attackDate)
        makeDataSetNoIPNetFlow(testingFile, startRFTesting, stopRFTesting, frequency, interval, "Testing", systemId, attackDate)
        calculationsRandomForestNoIPNetFlow(systemId, interval, attackDate)
        print("Finished Random Forest calculations without IPs")


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
        
        makeDataSetNetFlowEntropy(trainingFile, startRFTraining, stopRFTraining, frequency, interval, "Training", systemId, attackDate)
        makeDataSetNetFlowEntropy(testingFile, startRFTesting, stopRFTesting, frequency, interval, "Testing", systemId, attackDate)
        calculationRandomForestNetFlowEntropy(systemId, interval, attackDate)
        print("Finished Random Forest calculations on entropy")

        makeDataSetNetFlow(trainingFile, startRFTraining, stopRFTraining, frequency, interval, "Training", systemId, attackDate)
        makeDataSetNetFlow(testingFile, startRFTesting, stopRFTesting, frequency, interval, "Testing", systemId, attackDate)
        calculationsRandomForestNetFlow(systemId, interval, attackDate)
        print("Finished Random Forest calculations on all fields")

        makeDataSetNoIPNetFlow(trainingFile, startRFTraining, stopRFTraining, frequency, interval, "Training", systemId, attackDate)
        makeDataSetNoIPNetFlow(testingFile, startRFTesting, stopRFTesting, frequency, interval, "Testing", systemId, attackDate)
        calculationsRandomForestNoIPNetFlow(systemId, interval, attackDate)
        print("Finished Random Forest calculations without IPs")

#Attack 1
baseFile="two-days-2023-03-03_05-sorted.rw"         
systems = ["oslo-gw1"]
frequency = timedelta(minutes = 1)
interval = timedelta(minutes = 5)
pathToRawFiles="/home/linneafg/silk-data/RawDataFromFilter/"
attackDate="03.01.11" 

trainingBase="two-days-2023-03-03_05-sorted.rw"
testingBase="two-days-2023-03-03_05-sorted.rw"
'''startRFTraining = "2011-01-03 08:00:00"
stopRFTraining = "2011-01-03 12:00:00"
startRFTesting = "2011-01-03 12:00:00"
stopRFTesting = "2011-01-03 16:00:00"'''

startRFTraining = "2011-01-03 08:00:00"
stopRFTraining = "2011-01-03 12:00:00"
startRFTesting = "2011-01-04 08:00:00"
stopRFTesting = "2011-01-04 10:00:00"
randomForestMain(trainingBase, testingBase, systems, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequency, interval, pathToRawFiles, attackDate)

interval = timedelta(minutes = 10)
randomForestMain2(trainingBase, testingBase, systems, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequency, interval, pathToRawFiles, attackDate)

interval = timedelta(minutes = 15)
randomForestMain2(trainingBase, testingBase, systems, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequency, interval, pathToRawFiles, attackDate)