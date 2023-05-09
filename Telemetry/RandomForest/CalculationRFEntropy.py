from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, accuracy_score, recall_score, precision_score
import pandas as pd
import numpy as np
from datetime import timedelta,datetime

from HelperFunctions.StructureData import structureDataEntropy

'''
    Detect anomalies based on a random forest classifier
    Input:  
            trainingSet:    pandas dataframe, training data set
            testingSet:     pandas dataframe, testing data set
            systemId:       string, name of the system to collect and calculate on  
            interval:       timedelta object, size of the sliding window which the calculation is made on
            attackDate:     string, date of the attack the calculations are made on
'''
def calculationsRandomForestTelemetryEntropy(systemId, interval, attackDate):
    p = Path('Calculations')
    q = p / 'RandomForest' / 'Telemetry'
    if not q.exists():
        q.mkdir(parents=True)
    f = open(str(q) + "/Alerts.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #f_not = open(str(q) + "/NotAlerts.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f.write("sTime,eTime,entropy_rate_packet_size,real_label")
    #f_not.write("sTime,eTime,entropy_rate_packet_size,real_label")
    f_scores = open(str(q) + "/Score.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_scores.write("confusion_matrix,accuracy,f1,recall,precision")
    
    datasetsPath = Path('Telemetry')
    dsPath = datasetsPath / 'RandomForest' / 'DataSets'
    with open(str(dsPath) + "/Training/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl", 'rb') as trainingFile:
        trainingSet = pd.read_pickle(trainingFile)
    with open(str(dsPath) + "/Testing/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl", 'rb') as testingFile:
        testingSet = pd.read_pickle(testingFile)
    if len(trainingSet) ==0:
        return 
    if len(testingSet) ==0:
        return 
    
    trainingIntervals, trainingMeasurements, trainingLabel = structureDataEntropy(trainingSet) 
    trainingLabel=trainingLabel.astype('int')  

    testingIntervals, testingMeasurements, testingLabel = structureDataEntropy(testingSet)
    testingLabel=testingLabel.astype('int')  
    #Initialize a RF classifier and fit it to the training data set
    classifier_RF = RandomForestClassifier(n_estimators = 100)
    classifier_RF.fit(trainingMeasurements, trainingLabel)

    #Predict the label of the testing data set
    predictions = classifier_RF.predict(testingMeasurements)
    for i in range(len(predictions)):
        line = "\n"  + testingIntervals[i].left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," +testingIntervals[i].right.strftime("%Y-%m-%dT%H:%M:%SZ")
        for j in range(len(testingMeasurements[i])):
            line += "," + str(testingMeasurements[i][j])
        line += "," +str(testingLabel[i])

        if predictions[i] == 1:
            f.write(line)

    f.close()
    #f_not.close()
    f_scores.write("\n"+str(confusion_matrix(testingLabel, predictions)) + ","+ str(accuracy_score(testingLabel, predictions)) + ","+ 
                   str(f1_score(testingLabel,predictions)) + ","+ str(recall_score(testingLabel,predictions)) + ","+ 
                   str(precision_score(testingLabel,predictions)))
    f_scores.close()
