from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, accuracy_score, recall_score, precision_score
import pandas as pd
import numpy as np

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
    f0IP.write("sTime,eTime,srcIP,dstIP,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,nextHopIP,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,packet_size_entropy,packet_size_entropy_rate,real_label")

    datasetsPath = Path('NetFlow')
    dsPath = datasetsPath / 'RandomForest' / 'DataSets'
    with open(str(dsPath) + "/Training/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy", 'rb') as trainingFile:
        trainingSet = np.load(trainingFile, allow_pickle=True)
    if len(trainingSet) ==0:
        return
    
    trainingsTime, trainingeTime, trainingMeasurements, trainingLabel = structureDataNumpyArrays(trainingSet) 
    trainingLabel=trainingLabel.astype('int')  
    
    classifier_RF = RandomForestClassifier(n_estimators = estimator)
    classifier_RF.fit(trainingMeasurements,trainingLabel)

    for k in range(1,5):
        with open(str(dsPath) + "/Testing/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ "." + str(k) + ".npy", 'rb') as testingFile:
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
            for j in range(len(testingMeasurements[i])):
                lineIPs += "," + str(testingMeasurements[i][j])
            #line += "," +str(testingLabel[i])
            lineIPs += "," +str(testingLabel[i])
            if predictions[i] == 1:
                #f.write(line)
                f0IP.write(lineIPs)

    f0IP.close()