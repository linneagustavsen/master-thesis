from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import numpy as np
from datetime import timedelta,datetime

'''
    Detect anomalies based on a random forest classifier
    Input:  trainingSet:    pandas dataframe, training data set
            testingSet:     pandas dataframe, testing data set
            systemId:       string, name of the system to collect and calculate on  
            interval:       timedelta object, size of the sliding window which the calculation is made on
            attackDate:     string, date of the attack the calculations are made on
'''
def calculationRF(trainingSet, testingSet, systemId, interval, attackDate):
    f = open("Calculations/RandomForest/Telemetry/Alerts."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f.write("Time,egress_queue_info__0__avg_buffer_occupancy,egress_queue_info__0__cur_buffer_occupancy,egress_stats__if_1sec_pkts,egress_stats__if_1sec_octets,entropy_packet_size,entropy_rate_packet_size,real_label")

    #trainingSet = pd.read_pickle("Telemetry/RandomForest/Data/TrainingSet."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    trainingMeasurements = np.array(trainingSet.iloc[1:, 0:-1])
    trainingLabel = np.array(trainingSet.iloc[1:,-1])

    #Initialize a RF classifier and fit it to the training data set
    classifier_RF = RandomForestClassifier(n_estimators = 100)
    classifier_RF.fit(trainingMeasurements, trainingLabel)

    timeStamps = pd.read_pickle("Telemetry/RandomForest/RawData/Testing."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")["_time"].to_numpy()
    
    #testingSet = pd.read_pickle("Telemetry/RandomForest/Data/TestingSet."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    testingMeasurements = np.array(testingSet.iloc[1:,  0:-1])
    testingLabel = np.array(testingSet.iloc[1:,-1])

    #Predict the label of the testing data set
    predictions = classifier_RF.predict(testingMeasurements)
    for i in range(len(predictions)):
        if predictions[i] == 1:
            line = "\n"  + str(timeStamps[i])
            for j in range(len(testingMeasurements[i])):
                line += "," + str(testingMeasurements[i][j])
            line += "," +str(testingLabel[i])
            f.write(line)

    f.close()


trainingSet = "Telemetry/RandomForest/Data/TrainingSet.pkl"
testingSet = "Telemetry/RandomForest/Data/TestingSet.pkl"
systemId = "trd-gw"
interval = timedelta(minutes = 5)
attackDate = "21.09"
calculationRF(trainingSet, testingSet, systemId, interval, attackDate)