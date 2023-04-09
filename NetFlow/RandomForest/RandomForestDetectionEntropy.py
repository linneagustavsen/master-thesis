from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import numpy as np

'''
    Detect anomalies based on a random forest classifier and write them to file
    Input:  trainingSet:    pandas dataframe, training data set
            testingSet:     pandas dataframe, testing data set
            systemId:       string, name of the system to collect and detct on  
            interval:       timedelta object, size of the sliding window which the detection is made on
            attackDate:     string, date of the attack the detection are made on
'''
def detectionRandomForestNetFlowEntropy(trainingSet, testingSet, systemId, interval, attackDate):
    f = open("Detections/RandomForest/NetFlow/Alerts.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f.write("Time,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets,packet_size_entropy,packet_size_entropy_rate,number_of_packets,number_of_bytes,real_label")
    
    #trainingSet = pd.read_pickle("NetFlow/RandomForest/RawData/TrainingSet."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    trainingMeasurements = np.array(trainingSet.iloc[:, 0:-1])
    trainingLabel = np.array(trainingSet.iloc[:,-1])
    print(trainingMeasurements)
    print(trainingLabel)
    print(type(trainingLabel[0]))
    classifier_RF = RandomForestClassifier(n_estimators = 100)
    classifier_RF.fit(trainingMeasurements,trainingLabel)

    #testingSet = pd.read_pickle("NetFlow/RandomForest/RawData/TestingSet."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")

    timeStamps = pd.read_pickle("NetFlow/RandomForest/RawData/Training.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")["time"].to_numpy()

    testingMeasurements = np.array(testingSet.iloc[:, 0:-1])
    testingLabel = np.array(testingSet.iloc[:,-1])

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