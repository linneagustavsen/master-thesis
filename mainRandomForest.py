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

def randomForestMain(trainingBase, testingBase, systems, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequency, intervals, pathToRawFiles, attackDate):
    for systemId in systems:
        trainingFile = pathToRawFiles+systemId + "/"+ trainingBase
        testingFile = pathToRawFiles+systemId + "/"+ testingBase

        makeDataSetNetFlowFields(trainingFile, startRFTraining, stopRFTraining, "Training", systemId, attackDate)
        makeDataSetNetFlowFields(testingFile, startRFTesting, stopRFTesting, "Testing", systemId, attackDate)
        calculationRandomForestNetFlowFields(systemId, attackDate)
        print("Finished Random Forest calculations on fields")

        calculationRandomForestNoIPNetFlowFields(systemId, attackDate)
        print("Finished Random Forest calculations on fields without IPs")

        for interval in intervals:
            makeDataSetNetFlowEntropy(trainingFile, startRFTraining, stopRFTraining, frequency, interval, "Training", systemId, attackDate)
            makeDataSetNetFlowEntropy(testingFile, startRFTesting, stopRFTesting, frequency, interval, "Testing", systemId, attackDate)
            calculationRandomForestNetFlowEntropy(systemId, interval, attackDate)
            print("Finished Random Forest calculations on entropy")

            makeDataSetNetFlow(trainingFile, startRFTraining, stopRFTraining, frequency, interval, "Training", systemId, attackDate)
            makeDataSetNetFlow(testingFile, startRFTesting, stopRFTesting, frequency, interval, "Testing", systemId, attackDate)
            calculationsRandomForestNetFlow(systemId, interval, attackDate)
            print("Finished Random Forest calculations on all fields")

            calculationsRandomForestNoIPNetFlow(systemId, interval, attackDate)
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

            if os.path.exists("NetFlow/RandomForest/DataSets/Testing/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"):
                os.remove("NetFlow/RandomForest/DataSets/Testing/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy")
            else:
                print("The file NetFlow/RandomForest/DataSets/Testing/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy does not exist") 


        if os.path.exists("NetFlow/RandomForest/DataSets/Training/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"):
            os.remove("NetFlow/RandomForest/DataSets/Training/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".npy")
        else:
            print("The file NetFlow/RandomForest/DataSets/Training/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".npy does not exist") 
        
        if os.path.exists("NetFlow/RandomForest/DataSets/Testing/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"):
            os.remove("NetFlow/RandomForest/DataSets/Testing/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".npy")
        else:
            print("The file NetFlow/RandomForest/DataSets/Testing/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".npy does not exist") 



#Attack 1
baseFile="twelve-hours-2023-03-08_08-20-sorted.rw"     
systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
frequency = timedelta(minutes = 1)
intervals = [timedelta(minutes = 5), timedelta(minutes = 10), timedelta(minutes = 15)]
pathToRawFiles="/data/master-dump/master-thesis/tmp/data/"
attackDate="03.08.23" 

trainingBase="twelve-hours-2023-03-08_08-20-sorted.rw" 
testingBase="twelve-hours-2023-03-08_08-20-sorted.rw" 

startRFTraining = "2023-03-08 14:00:00"
stopRFTraining = "2023-03-08 15:00:00"
startRFTesting = "2023-03-08 15:00:00"
stopRFTesting = "2023-03-08 16:00:00"
randomForestMain(trainingBase, testingBase, systems, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequency, intervals, pathToRawFiles, attackDate)
