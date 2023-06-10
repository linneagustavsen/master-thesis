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

    f = open(str(q) + "/Alerts.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #f.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,packet_size_entropy,packet_size_entropy_rate,real_label")
    f.write("sTime,eTime,packets,real_label")
    #f_not = open(str(q) + "/NotAlerts.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #f_not.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,packet_size_entropy,packet_size_entropy_rate,real_label")
    #f0IP = open(str(ipPath) + "/Alerts.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #f1IP = open(str(ipPath) + "/NotAlerts.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #f0IP.write("sTime,eTime,srcIP,dstIP,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,nextHopIP,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,packet_size_entropy,packet_size_entropy_rate,real_label")
    #f1IP.write("sTime,eTime,srcIP,dstIP,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,nextHopIP,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,packet_size_entropy,packet_size_entropy_rate,real_label")
    f_scores = open(str(q) + "/Score.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_scores.write("confusion_matrix,accuracy,f1,recall,precision")

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
    classifier_RF = pickle.load(open(filename, 'rb'))

    for k in range(1,9):
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
            line = "\n"  + sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ") + "," + eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")
            #lineIPs = "\n"  + sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ") + "," + eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")
            '''for j in range(len(testingMeasurements[i])):
                #lineIPs += "," + str(testingMeasurements[i][j])
                #Skip the IP fields
                if j == 0 or j == 1 or j == 16:
                    continue
                line += "," + str(testingMeasurements[i][j])'''
            line += "," + str(testingMeasurements[i][5])
            line += "," +str(testingLabel[i])
            #lineIPs += "," +str(testingLabel[i])
            if predictions[i] == 1:
                f.write(line)
                #f0IP.write(lineIPs)
            '''if predictions[i] == 0:
                f_not.write(line)
                f1IP.write(lineIPs)'''

    f.close()
    #f_not.close()
    #f0IP.close()
    #f1IP.close()

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
            systemId:       string, name of the system to collect and calculate on  
            interval:       timedelta object, size of the sliding window which the calculation is made on
            attackDate:     string, date of the attack the calculations are made on
'''
def calculationsRandomForestNoIPNetFlow(systemId, interval, attackDate, estimator):
    p = Path('Calculations')
    q = p / 'RandomForest' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    f = open(str(q) + "/AlertsNoIP.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #f.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,packet_size_entropy,packet_size_entropy_rate,real_label")
    f.write("sTime,eTime,packets,real_label")
    #f_not = open(str(q) + "/NotAlertsNoIP.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #f_not.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,packet_size_entropy,packet_size_entropy_rate,real_label")
    f_scores = open(str(q) + "/ScoreNoIP.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_scores.write("confusion_matrix,accuracy,f1,recall,precision")

    datasetsPath = Path('NetFlow')
    dsPath = datasetsPath / 'RandomForest' / 'DataSets'

    '''fieldsFile = str(dsPath) + "/Training/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"
    fieldsFileNoIP = str(dsPath) + "/Training/CombinedNoIP."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"
    if Path(fieldsFileNoIP).exists():
        with open(str(fieldsFileNoIP), 'rb') as trainingFile:
            trainingSet = np.load(trainingFile, allow_pickle=True)
        if len(trainingSet) ==0:
            return 
    elif Path(fieldsFile).exists():
        with open(str(fieldsFile), 'rb') as trainingFile:
            df0 = np.load(trainingFile, allow_pickle=True)
        if len(df0) ==0:
            return
        df1 = np.delete(df0, np.s_[2:4], 1)
        trainingSet = np.delete(df1, 16, 1)

    if len(trainingSet) ==0:
        return 
    
    trainingsTime, trainingeTime, trainingMeasurements, trainingLabel = structureDataNumpyArrays(trainingSet)    
    trainingLabel=trainingLabel.astype('int')

    classifier_RF = RandomForestClassifier(n_estimators = estimator)
    classifier_RF.fit(trainingMeasurements,trainingLabel)'''

    modelPath = datasetsPath / 'RandomForest' / 'Models'
    if not modelPath.exists():
        modelPath.mkdir(parents=True)
    filename = str(modelPath) + "/CombinedNoIP."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl"
    classifier_RF = pickle.load(open(filename, 'rb'))

    for k in range(1,9):
        fieldsFileTesting = str(dsPath) + "/Testing/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ "." + str(k) + ".npy"
        fieldsFileNoIPTesting = str(dsPath) + "/Testing/CombinedNoIP."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ "." + str(k) + ".npy"
        if Path(fieldsFileNoIPTesting).exists():
            with open(str(fieldsFileNoIPTesting), 'rb') as testingFile:
                testingSet = np.load(testingFile, allow_pickle=True)
            if len(testingSet) ==0:
                print("Testing set is empty")
                return 
        elif Path(fieldsFileTesting).exists():
            with open(str(fieldsFileTesting), 'rb') as testingFile:
                df2 = np.load(testingFile, allow_pickle=True)
            if len(df2) ==0:
                print("Testing set is empty")
                return
            df3 = np.delete(df2, np.s_[2:4],1)
            testingSet = np.delete(df3, 16, 1)

        
        if len(testingSet) ==0:
            print("Testing set is empty")
            continue 
        
        sTime, eTime, testingMeasurements, testingLabel = structureDataNumpyArrays(testingSet)    
        testingLabel=testingLabel.astype('int')  

        sTime = pd.to_datetime(sTime)
        eTime = pd.to_datetime(eTime)

        predictions = classifier_RF.predict(testingMeasurements)
        for i in range(len(predictions)):
            line = "\n"  + sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ") + "," + eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")
            '''for j in range(len(testingMeasurements[i])):
                line += "," + str(testingMeasurements[i][j])'''
            line += "," + str(testingMeasurements[i][3])
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
