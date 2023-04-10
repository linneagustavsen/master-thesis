from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import numpy as np
from datetime import timedelta,datetime

'''
    Detect anomalies based on a random forest classifier
    Input:  
            trainingSet:    pandas dataframe, training data set
            testingSet:     pandas dataframe, testing data set
            systemId:       string, name of the system to collect and calculate on  
            interval:       timedelta object, size of the sliding window which the calculation is made on
            attackDate:     string, date of the attack the calculations are made on
'''
def detectionRandomForestTelemetry(trainingSet, testingSet, systemId, interval, attackDate):
    f = open("Detections/RandomForest/Telemetry/Alerts."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_not = open("Detections/RandomForest/Telemetry/NotAlerts."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f.write("Time,egress_queue_info__0__avg_buffer_occupancy,egress_queue_info__0__cur_buffer_occupancy,egress_stats__if_1sec_pkts,egress_stats__if_1sec_octets,entropy_packet_size,entropy_rate_packet_size,real_label")
    f_not.write("Time,egress_queue_info__0__avg_buffer_occupancy,egress_queue_info__0__cur_buffer_occupancy,egress_stats__if_1sec_pkts,egress_stats__if_1sec_octets,entropy_packet_size,entropy_rate_packet_size,real_label")

    trainingMeasurements = np.array(trainingSet.iloc[:, 0:-1])
    trainingLabel = np.array(trainingSet.iloc[:,-1])

    #Initialize a RF classifier and fit it to the training data set
    classifier_RF = RandomForestClassifier(n_estimators = 100)
    classifier_RF.fit(trainingMeasurements, trainingLabel)

    timeStamps = pd.read_pickle("Telemetry/RandomForest/RawData/Testing."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")["_time"].to_numpy()
    
    testingMeasurements = np.array(testingSet.iloc[:, 0:-1])
    testingLabel = np.array(testingSet.iloc[:,-1])

    #Predict the label of the testing data set
    predictions = classifier_RF.predict(testingMeasurements)
    for i in range(len(predictions)):
        if predictions[i] == 1:
            print("One alert at index:", i, "this had label", testingLabel[i], "in the testing data set")
            line = "\n"  + timeStamps[i].strftime("%Y-%m-%dT%H:%M:%SZ")
            for j in range(len(testingMeasurements[i])):
                line += "," + str(testingMeasurements[i][j])
            line += "," +str(testingLabel[i])
            f.write(line)
        if predictions[i] == 0:
            line = "\n"  + timeStamps[i].strftime("%Y-%m-%dT%H:%M:%SZ")
            for j in range(len(testingMeasurements[i])):
                line += "," + str(testingMeasurements[i][j])
            line += "," +str(testingLabel[i])
            f_not.write(line)

    f.close()
    f_not.close()


'''trainingSet = "Telemetry/RandomForest/Data/TrainingSet.pkl"
testingSet = "Telemetry/RandomForest/Data/TestingSet.pkl"
systemId = "trd-gw"
interval = timedelta(minutes = 5)
attackDate = "21.09"
detectionRFTelemetry(trainingSet, testingSet, systemId, interval, attackDate)'''