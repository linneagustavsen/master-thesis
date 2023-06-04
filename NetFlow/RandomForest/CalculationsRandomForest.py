from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, accuracy_score, recall_score, precision_score
import pandas as pd
import numpy as np
import pickle

from HelperFunctions.StructureData import structureDataNumpyArrays

'''
    Detect anomalies based on a random forest classifier and write them to file
    Input:  
            trainingSet:    pandas dataframe, training data set
            testingSet:     pandas dataframe, testing data set
            systemId:       string, name of the system to collect and calculate on  
            interval:       timedelta object, size of the sliding window which the calculation is made on
            attackDate:     string, date of the attack the calculations are made on
'''
def calculationsRandomForestNetFlow(systemId, interval, attackDate, estimator):
    p = Path('Calculations')
    q = p / 'RandomForest' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    ipP = Path('IPCalculations')
    ipPath = ipP / 'RandomForest'
    if not ipPath.exists():
        ipPath.mkdir(parents=True, exist_ok=False)

    f0IP = open(str(ipPath) + "/Alerts.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f0IP.write("sTime,eTime,srcIP,dstIP,nextHopIP,real_label")

    datasetsPath = Path('NetFlow')
    dsPath = datasetsPath / 'RandomForest' / 'DataSets'
    
    '''with open(str(dsPath) + "/Training/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy", 'rb') as trainingFile:
        trainingSet = np.load(trainingFile, allow_pickle=True)
    if len(trainingSet) ==0:
        return
    
    trainingsTime, trainingeTime, trainingMeasurements, trainingLabel = structureDataNumpyArrays(trainingSet) 
    trainingLabel=trainingLabel.astype('int')  
    
    classifier_RF = RandomForestClassifier(n_estimators = estimator)
    classifier_RF.fit(trainingMeasurements,trainingLabel)'''

    modelPath = datasetsPath / 'RandomForest' / 'Models'
    if not modelPath.exists():
        modelPath.mkdir(parents=True)
    filename = str(modelPath) + "/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl"
    if not Path(filename).exists():
        print("There is no model")
        return
    classifier_RF = pickle.load(open(filename, 'rb'))

    for k in range(1,9):
        testingFilePath = str(dsPath) + "/Testing/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ "." + str(k) + ".npy"
        if not Path(testingFilePath).exists():
            print("There is no data for this period")
            continue
        with open(testingFilePath, 'rb') as testingFile:
            testingSet = np.load(testingFile, allow_pickle=True)
        
        if len(testingSet) ==0:
            continue

        sTime, eTime, testingMeasurements, testingLabel = structureDataNumpyArrays(testingSet)
        testingLabel=testingLabel.astype('int')    

        sTime = pd.to_datetime(sTime)
        eTime = pd.to_datetime(eTime)

        predictions = classifier_RF.predict(testingMeasurements)
        for i in range(len(predictions)):
            #line = "\n"  + sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ") + "," + eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")
            lineIPs = "\n"  + sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ") + "," + eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")
            '''for j in range(len(testingMeasurements[i])):
                lineIPs += "," + str(testingMeasurements[i][j])'''
            lineIPs += "," + str(testingMeasurements[i][0])
            lineIPs += "," + str(testingMeasurements[i][1])
            lineIPs += "," + str(testingMeasurements[i][16])
            #line += "," +str(testingLabel[i])
            lineIPs += "," +str(testingLabel[i])
            if predictions[i] == 1:
                #f.write(line)
                f0IP.write(lineIPs)

    f0IP.close()
