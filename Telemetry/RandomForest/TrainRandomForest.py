from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import numpy as np
from datetime import timedelta,datetime
import json
import paho.mqtt.client as mqtt
import pickle

'''
    Detect anomalies based on a random forest classifier
    Input:  
            trainingSet:    pandas dataframe, training data set
            systemId:       string, name of the system to train the model on
'''
def trainRandomForestTelemetry(trainingSet, systemId):
    trainingMeasurements = np.array(trainingSet.iloc[:, 0:-1])
    trainingLabel = np.array(trainingSet.iloc[:,-1])

    #Initialize a RF classifier and fit it to the training data set
    classifier_RF = RandomForestClassifier(n_estimators = 100)
    classifier_RF.fit(trainingMeasurements, trainingLabel)

    filename = "Telemetry/RandomForest/Models/RandomForestModel."+str(systemId)+ ".pkl"
    pickle.dump(classifier_RF, open(filename, 'wb'))


'''trainingSet = "Telemetry/RandomForest/Data/TrainingSet.pkl"
testingSet = "Telemetry/RandomForest/Data/TestingSet.pkl"
systemId = "trd-gw"
interval = timedelta(minutes = 5)
attackDate = "21.09"
detectionRFTelemetry(trainingSet, testingSet, systemId, interval, attackDate)'''