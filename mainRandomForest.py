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
import os

def randomForestMain(trainingBase, testingBase, estimators, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequencies, interval, pathToRawFiles, attackDate):
    systemId = "teknobyen-gw1"
    trainingFile = pathToRawFiles+systemId + "/"+ trainingBase
    testingFile = pathToRawFiles+systemId + "/"+ testingBase
    for frequency in frequencies:
        print("Frequency")
        print(frequency)
        makeDataSetNetFlowEntropy(trainingFile, startRFTraining, stopRFTraining, frequency, interval, "Training", systemId, attackDate)
        makeDataSetNetFlowEntropy(testingFile, startRFTesting, stopRFTesting, frequency, interval, "Testing", systemId, attackDate)
            
        for estimator in estimators:
            print("Estimator")
            print(estimator)
            calculationRandomForestNetFlowEntropy(systemId, interval, attackDate, estimator)
            print("Finished Random Forest calculations on entropy")

           

#Attack 1
baseFile="twelve-hours-2023-03-08_08-20-sorted.rw"     
estimators = [50,100,300]
frequencies = [timedelta(seconds = 5),timedelta(seconds = 10), timedelta(seconds = 15),timedelta(seconds = 30),timedelta(seconds = 35),
               timedelta(seconds = 40),timedelta(seconds = 45),timedelta(seconds = 50),timedelta(seconds = 55),timedelta(minutes = 1)]
interval = timedelta(minutes = 5)
pathToRawFiles="/data/master-dump/master-thesis/tmp/data/"
attackDate="03.08.23" 

trainingBase="twelve-hours-2023-03-08_08-20-sorted.rw" 
testingBase="twelve-hours-2023-03-08_08-20-sorted.rw" 

startRFTraining = "2023-03-08 14:00:00"
stopRFTraining = "2023-03-08 15:00:00"
startRFTesting = "2023-03-08 15:00:00"
stopRFTesting = "2023-03-08 16:00:00"
randomForestMain(trainingBase, testingBase, estimators, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequencies, interval, pathToRawFiles, attackDate)
