from NetFlow.RandomForest.CalculationsRandomForest import calculationsRandomForestNetFlow
from NetFlow.RandomForest.CalculationsRandomForestFields import calculationRandomForestNetFlowFields
from NetFlow.RandomForest.MakeDataSet import makeDataSetNetFlow
from NetFlow.RandomForest.MakeDataSetFields import makeDataSetNetFlowFields
from NetFlow.RandomForest.MakeTestingDataSet import makeTestingDataSetNetFlow
from NetFlow.RandomForest.MakeTestingDataSetFields import makeTestingDataSetNetFlowFields
from NetFlow.RandomForest.TrainFields import trainFields
from NetFlow.Threshold.SYNCalculation import synCalculation
from NetFlow.Threshold.XmasCalculation import xmasCalculation
from NetFlow.TopKFlows.topkflowCalculation import topkflows2
from datetime import datetime, timedelta
import math
import os
from NetFlow.Kmeans.CalculationsKmeans import kmeansCalculation
from NetFlow.Kmeans.CalculationsKmeansCombined import kmeansCombinedCalculation

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
def main(baseFile, systems, start, stop, frequency, pathToRawFiles, attackDate):
    for systemId in systems:
        print(systemId)
        silkFile = pathToRawFiles+systemId + "/"+ baseFile
        silkFileSyn = pathToRawFiles+systemId + "/tcp-syn-"+ baseFile
        #SYN calculation
        synCalculation(silkFileSyn, start, stop, systemId, attackDate)
        print("Finished SYN calculations")
        #TopKflows
        topkflows2(silkFile, start, stop, frequency, 20, attackDate, systemId)
        print("Finished top k flows")
        xmasCalculation(silkFile, start, stop, systemId, attackDate)
        print("Finished Xmas calculation")

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
        stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S') + timedelta(minutes=15)
        intervalTime = (stopTime - startTime).total_seconds()/timedelta(minutes=15).total_seconds()
    
        for i in range(math.ceil(intervalTime)):
            stopTime = startTime + timedelta(minutes=15)
            if os.path.exists("NetFlow/Kmeans/DataSets/Fields.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".npy"):
                os.remove("NetFlow/Kmeans/DataSets/Fields.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".npy")
            else:
                print("The file NetFlow/Kmeans/DataSets/Fields.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".npy does not exist") 
            startTime += timedelta(minutes=15)

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

        for interval in intervals:
            print(interval)

            makeDataSetNetFlow(trainingFile, startRFTraining, stopRFTraining, frequency, interval, "Training", systemId, attackDate)
            makeTestingDataSetNetFlow(testingFile, startRFTesting, stopRFTesting, frequency, interval, "Testing", systemId, attackDate)
            calculationsRandomForestNetFlow(systemId, interval, attackDate, estimator)
            print("Finished Random Forest calculations on all fields")

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

#Attack number 3
baseFile="2023-03-24_14-18-sorted.rw"         
systems = ["bergen-gw3", "hoytek-gw2", "hovedbygget-gw", "trd-gw", "teknobyen-gw2", "teknobyen-gw1", "ifi2-gw5", 
            "oslo-gw1", "tromso-gw5", "stangnes-gw", "rodbergvn-gw2", "narvik-kv-gw", "narvik-gw3", "tromso-fh-gw",
            "ma2-gw", "narvik-gw4"]
start = "2023-03-24 14:00:00"
stop = "2023-03-24 18:00:00"
frequency = timedelta(minutes = 1)
interval = timedelta(minutes = 5)
pathToRawFiles="/data/master-dump/fresh-netflow-data/master-dump/"
attackDate="24.03.23"

main(baseFile, systems, start, stop, frequency, pathToRawFiles, attackDate)       

intervals = [timedelta(minutes = 5), timedelta(minutes = 10), timedelta(minutes = 15)]
clusterFrequency = timedelta(minutes = 15)
kmeansMain(baseFile, systems, start, stop, clusterFrequency, frequency, intervals, pathToRawFiles, attackDate)  

estimator = 100
trainingBase="2023-03-17_11-14-sorted.rw" 
testingBase="2023-03-24_14-18-sorted.rw" 

startRFTraining = "2023-03-17 11:00:00"
stopRFTraining = "2023-03-17 13:00:00"
startRFTesting = "2023-03-24 14:00:00"
stopRFTesting = "2023-03-24 18:00:00"
randomForestMain(trainingBase, testingBase, estimator, startRFTraining, stopRFTraining, startRFTesting, stopRFTesting, frequency, intervals, systems, pathToRawFiles, attackDate)