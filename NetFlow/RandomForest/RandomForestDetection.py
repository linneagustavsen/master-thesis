from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import numpy as np

'''
    Detect anomalies based on a random forest classifier and write them to file
    Input:  trainingSet:    pandas dataframe, training data set
            testingSet:     pandas dataframe, testing data set
            systemId:       string, name of the system to collect and detct on  
            attackDate:     string, date of the attack the detection are made on
'''
def detectionRandomForestNetFlowFields(trainingSet, testingSet, systemId, attackDate):
    f = open("Detections/RandomForest/NetFlow/Alerts.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f.write("Time,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,real_label")
    
    #trainingSet = pd.read_pickle("NetFlow/RandomForest/RawData/TrainingSet."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    trainingMeasurements = np.array(trainingSet.iloc[1:, 0:-1])
    trainingLabel = np.array(trainingSet.iloc[1:,-1])

    classifier_RF = RandomForestClassifier(n_estimators = 100)
    classifier_RF.fit(trainingMeasurements,trainingLabel)

    #testingSet = pd.read_pickle("NetFlow/RandomForest/RawData/TestingSet."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")

    timeStamps = pd.read_pickle("NetFlow/RandomForest/RawData/Testing.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")["sTime"].to_numpy()

    testingMeasurements = np.array(testingSet.iloc[1:, 0:-1])
    testingLabel = np.array(testingSet.iloc[1:,-1])

    predictions = classifier_RF.predict(testingMeasurements)
    for i in range(len(predictions)):
        if predictions[i] == 1:
            line = "\n"  + timeStamps[i].strftime("%Y-%m-%dT%H:%M:%SZ")
            for j in range(len(testingMeasurements[i])):
                if j == 0 or j == 1 or j == 16:
                    continue
                line += "," + str(testingMeasurements[i][j])
            line += "," +str(testingLabel[i])
        
            f.write(line)

    f.close()

'''
    Detect anomalies based on a random forest classifier and write them to file
    Specifically without IPs
    Input:  trainingSet:    pandas dataframe, training data set
            testingSet:     pandas dataframe, testing data set
            systemId:       string, name of the system to collect and detect on  
            attackDate:     string, date of the attack the detections are made on
'''
def detectionRandomForestNoIPNetFlowFields(trainingSet, testingSet, systemId, attackDate):
    f = open("Detections/RandomForest/NetFlow/AlertsNoIP.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f.write("Time,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,real_label")
    
    #trainingSet = pd.read_pickle("NetFlow/RandomForest/RawData/TrainingSet."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    trainingMeasurements = np.array(trainingSet.iloc[1:, 0:-1])

    trainingLabel = np.array(trainingSet.iloc[1:,-1])

    classifier_RF = RandomForestClassifier(n_estimators = 100)
    classifier_RF.fit(trainingMeasurements,trainingLabel)

    #testingSet = pd.read_pickle("NetFlow/RandomForest/RawData/TestingSet."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")

    timeStamps = pd.read_pickle("NetFlow/RandomForest/RawData/NoIPTesting.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")["sTime"].to_numpy()

    testingMeasurements = np.array(testingSet.iloc[1:,  0:-1])
    testingLabel = np.array(testingSet.iloc[1:,-1])

    predictions = classifier_RF.predict(testingMeasurements)
    for i in range(len(predictions)):
        if predictions[i] == 1:
            line = "\n"  + timeStamps[i].strftime("%Y-%m-%dT%H:%M:%SZ")
            for j in range(len(testingMeasurements[i])):
                line += "," + str(testingMeasurements[i][j])
            line += "," +str(testingLabel[i])
        
            f.write(line)

    f.close()
