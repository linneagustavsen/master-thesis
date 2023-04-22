from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import numpy as np

'''
    Detect anomalies based on a random forest classifier and write them to file
    Input:  
            trainingSet:    pandas dataframe, training data set
            testingSet:     pandas dataframe, testing data set
            systemId:       string, name of the system to collect and detct on  
            attackDate:     string, date of the attack the detection are made on
'''
def calculationRandomForestNetFlowFields(trainingSet, testingSet, systemId, attackDate):
    p = Path('Calculations')
    q = p / 'RandomForest' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    f = open(str(q) + "/Alerts.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,real_label")
    f_not = open(str(q) + "/NotAlerts.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_not.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,real_label")
    
    trainingMeasurements = np.array(trainingSet.iloc[:, 0:-1])
    trainingLabel = np.array(trainingSet.iloc[:,-1])

    classifier_RF = RandomForestClassifier(n_estimators = 100)
    classifier_RF.fit(trainingMeasurements,trainingLabel)

    p = Path('NetFlow')
    q = p / 'RandomForest' / 'RawData'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    sTime = pd.read_pickle(str(q) + "/Testing.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")["sTime"].to_numpy()
    eTime = pd.read_pickle(str(q) + "/Testing.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")["eTime"].to_numpy()
    sTime = pd.to_datetime(sTime)
    eTime = pd.to_datetime(eTime)

    testingMeasurements = np.array(testingSet.iloc[:, 0:-1])
    testingLabel = np.array(testingSet.iloc[:,-1])

    predictions = classifier_RF.predict(testingMeasurements)
    for i in range(len(predictions)):
        line = "\n"  + sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ") + "," + eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")
        for j in range(len(testingMeasurements[i])):
            #Skip the IP fields
            if j == 0 or j == 1 or j == 16:
                continue
            line += "," + str(testingMeasurements[i][j])
        line += "," +str(testingLabel[i])

        if predictions[i] == 1:        
            f.write(line)
        if predictions[i] == 0:
            f_not.write(line)

    f.close()
    f_not.close()

'''
    Detect anomalies based on a random forest classifier and write them to file
    Specifically without IPs
    Input:  
            trainingSet:    pandas dataframe, training data set
            testingSet:     pandas dataframe, testing data set
            systemId:       string, name of the system to collect and detect on  
            attackDate:     string, date of the attack the detections are made on
'''
def calculationRandomForestNoIPNetFlowFields(trainingSet, testingSet, systemId, attackDate):
    p = Path('Calculations')
    q = p / 'RandomForest' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    f = open(str(q) + "/AlertsNoIP.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,real_label")
    f_not = open(str(q) + "/NotAlertsNoIP.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_not.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,real_label")
    
    trainingMeasurements = np.array(trainingSet.iloc[:, 0:-1])

    trainingLabel = np.array(trainingSet.iloc[:,-1])

    classifier_RF = RandomForestClassifier(n_estimators = 100)
    classifier_RF.fit(trainingMeasurements,trainingLabel)

    p = Path('NetFlow')
    q = p / 'RandomForest' / 'RawData'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    sTime = pd.read_pickle(str(q) + "/NoIPTesting.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")["sTime"].to_numpy()
    eTime = pd.read_pickle(str(q) + "/NoIPTesting.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")["eTime"].to_numpy()
    sTime = pd.to_datetime(sTime)
    eTime = pd.to_datetime(eTime)

    testingMeasurements = np.array(testingSet.iloc[:,  0:-1])
    testingLabel = np.array(testingSet.iloc[:,-1])

    predictions = classifier_RF.predict(testingMeasurements)
    for i in range(len(predictions)):
        line = "\n"  + sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ") + "," + eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")
        for j in range(len(testingMeasurements[i])):
            line += "," + str(testingMeasurements[i][j])
        line += "," +str(testingLabel[i])
        
        if predictions[i] == 1:
            f.write(line)
        if predictions[i] == 0:
           f_not.write(line)

    f.close()
    f_not.close()