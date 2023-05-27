from pathlib import Path
import pickle
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
            systemId:       string, name of the system to collect and detct on  
            attackDate:     string, date of the attack the detection are made on
'''
def calculationRandomForestNetFlowFields(systemId, attackDate, estimator):
    p = Path('Calculations')
    q = p / 'RandomForest' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    ipP = Path('IPCalculations')
    ipPath = ipP / 'RandomForest'
    if not ipPath.exists():
        ipPath.mkdir(parents=True, exist_ok=False)

    f = open(str(q) + "/Alerts.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,real_label")
    '''f_not = open(str(q) + "/NotAlerts.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_not.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,real_label")
    f0IP = open(str(ipPath) + "/Alerts.Combined.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f1IP = open(str(ipPath) + "/NotAlerts.Combined.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f0IP.write("sTime,eTime,srcIP,dstIP,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,nextHopIP,real_label")
    f1IP.write("sTime,eTime,srcIP,dstIP,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,nextHopIP,real_label")'''
    
    f_scores = open(str(q) + "/Score.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_scores.write("confusion_matrix,accuracy,f1,recall,precision")
    
    datasetsPath = Path('NetFlow')
    dsPath = datasetsPath / 'RandomForest' / 'DataSets'
    
    modelPath = datasetsPath / 'RandomForest' / 'Models'
    if not modelPath.exists():
        modelPath.mkdir(parents=True)
    filename = str(modelPath) + "/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl"
    classifier_RF = pickle.load(open(filename, 'rb'))

    for k in range(1,9):
        with open(str(dsPath) + "/Testing/Fields.attack."+str(attackDate)+ "."+str(systemId)+ "." + str(k)+".npy", 'rb') as testingFile:
            testingSet = np.load(testingFile, allow_pickle=True)

        if len(testingSet) ==0:
            return 
        
        sTime, eTime, testingMeasurements, testingLabel = structureDataNumpyArrays(testingSet)    
        testingLabel=testingLabel.astype('int')  

        sTime = pd.to_datetime(sTime)
        eTime = pd.to_datetime(eTime)

        predictions = classifier_RF.predict(testingMeasurements)
        for i in range(len(predictions)):
            line = "\n"  + sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ") + "," + eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")
            #lineIPs = "\n"  + sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ") + "," + eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")
            for j in range(len(testingMeasurements[i])):
                #lineIPs += "," + str(testingMeasurements[i][j])
                #Skip the IP fields
                if j == 0 or j == 1 or j == 16:
                    continue
                line += "," + str(testingMeasurements[i][j])
            line += "," +str(testingLabel[i])
            #lineIPs += "," +str(testingLabel[i])

            if predictions[i] == 1:        
                f.write(line)
                #f0IP.write(lineIPs)
            '''if predictions[i] == 0:
                f_not.write(line)
                f1IP.write(lineIPs)'''

    f.close()
    '''f_not.close()
    f0IP.close()
    f1IP.close()'''
    f_scores.write("\n"+str(confusion_matrix(testingLabel, predictions)) + ","+ str(accuracy_score(testingLabel, predictions)) + ","+ 
                   str(f1_score(testingLabel,predictions)) + ","+ str(recall_score(testingLabel,predictions)) + ","+ 
                   str(precision_score(testingLabel,predictions)))
    f_scores.close()

'''
    Detect anomalies based on a random forest classifier and write them to file
    Specifically without IPs
    Input:  
            trainingSet:    pandas dataframe, training data set
            testingSet:     pandas dataframe, testing data set
            systemId:       string, name of the system to collect and detect on  
            attackDate:     string, date of the attack the detections are made on
'''
def calculationRandomForestNoIPNetFlowFields(systemId, attackDate, estimator):
    p = Path('Calculations')
    q = p / 'RandomForest' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    f = open(str(q) + "/AlertsNoIP.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,real_label")
    '''f_not = open(str(q) + "/NotAlertsNoIP.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_not.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,real_label")'''
    f_scores = open(str(q) + "/ScoreNoIP.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_scores.write("confusion_matrix,accuracy,f1,recall,precision")

    datasetsPath = Path('NetFlow')
    dsPath = datasetsPath / 'RandomForest' / 'DataSets'

    modelPath = datasetsPath / 'RandomForest' / 'Models'
    if not modelPath.exists():
        modelPath.mkdir(parents=True)
    filename = str(modelPath) + "/FieldsNoIP.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl"
    classifier_RF = pickle.load(open(filename, 'rb'))

    for k in range(1,9):
        fieldsFileTesting = str(dsPath) + "/Testing/Fields.attack."+str(attackDate)+ "."+str(systemId)+ "." + str(k)+".npy"
        fieldsFileNoIPTesting = str(dsPath) + "/Testing/FieldsNoIP.attack."+str(attackDate)+ "."+str(systemId)+ "." + str(k)+".npy"
        if Path(fieldsFileNoIPTesting).exists():
            with open(str(fieldsFileNoIPTesting), 'rb') as testingFile:
                testingSet = np.load(testingFile, allow_pickle=True)
        elif Path(fieldsFileTesting).exists():
            with open(str(fieldsFileTesting), 'rb') as testingFile:
                df2 = np.load(testingFile, allow_pickle=True)
            if len(df2) ==0:
                return 
            df3 = np.delete(df2, np.s_[2:4],1)
            testingSet = np.delete(df3, -2,1)
            

        sTime, eTime, testingMeasurements, testingLabel = structureDataNumpyArrays(testingSet)    
        testingLabel=testingLabel.astype('int')  

        sTime = pd.to_datetime(sTime)
        eTime = pd.to_datetime(eTime)

        predictions = classifier_RF.predict(testingMeasurements)
        for i in range(len(predictions)):
            line = "\n"  + sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ") + "," + eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")
            for j in range(len(testingMeasurements[i])):
                line += "," + str(testingMeasurements[i][j])
            line += "," +str(testingLabel[i])
            
            if predictions[i] == 1:
                f.write(line)
            '''if predictions[i] == 0:
            f_not.write(line)'''

    f.close()
    #f_not.close()
    f_scores.write("\n"+str(confusion_matrix(testingLabel, predictions)) + ","+ str(accuracy_score(testingLabel, predictions)) + ","+ 
                   str(f1_score(testingLabel,predictions)) + ","+ str(recall_score(testingLabel,predictions)) + ","+ 
                   str(precision_score(testingLabel,predictions)))
    f_scores.close()