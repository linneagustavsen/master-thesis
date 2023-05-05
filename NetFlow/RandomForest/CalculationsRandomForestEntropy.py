from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, accuracy_score, recall_score, precision_score
import pandas as pd
import numpy as np

from HelperFunctions.StructureData import structureDataEntropyNumpyArrays

'''
    Detect anomalies based on a random forest classifier and write them to file
    Input:  
            trainingSet:    pandas dataframe, training data set
            testingSet:     pandas dataframe, testing data set
            systemId:       string, name of the system to collect and calculate on  
            interval:       timedelta object, size of the sliding window which the calculation is made on
            attackDate:     string, date of the attack the calculation are made on
'''
def calculationRandomForestNetFlowEntropy(systemId, interval, attackDate):
    p = Path('Calculations')
    q = p / 'RandomForest' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    f = open(str(q) + "/Alerts.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f.write("sTime,eTime,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets,packet_size_entropy,packet_size_entropy_rate,number_of_packets,number_of_bytes,real_label")
    #f_not = open(str(q) + "/NotAlerts.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #f_not.write("sTime,eTime,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets,packet_size_entropy,packet_size_entropy_rate,number_of_packets,number_of_bytes,real_label")
    f_scores = open(str(q) + "/Score.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_scores.write("confusion_matrix,accuracy,f1,recall,precision")
    
    datasetsPath = Path('NetFlow')
    dsPath = datasetsPath / 'RandomForest' / 'DataSets'
    with open(str(dsPath) + "/Training/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy", 'rb') as f:
        trainingSet = np.load(f, allow_pickle=True)
    with open(str(dsPath) + "/Testing/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy", 'rb') as f:
        testingSet = np.load(f, allow_pickle=True)
    if len(trainingSet) ==0:
        return 
    if len(testingSet) ==0:
        return 
    
    trainingIntervals, trainingMeasurements, trainingLabel = structureDataEntropyNumpyArrays(trainingSet)    
    trainingLabel=trainingLabel.astype('int')  

    testingIntervals, testingMeasurements, testingLabel = structureDataEntropyNumpyArrays(testingSet)    
    testingLabel=testingLabel.astype('int')  

    classifier_RF = RandomForestClassifier(n_estimators = 100)
    classifier_RF.fit(trainingMeasurements,trainingLabel)

    predictions = classifier_RF.predict(testingMeasurements)
    for i in range(len(predictions)):
        line = "\n"  + testingIntervals[i].left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," +testingIntervals[i].right.strftime("%Y-%m-%dT%H:%M:%SZ")
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