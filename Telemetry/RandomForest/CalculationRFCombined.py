from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, accuracy_score, recall_score, precision_score
import pandas as pd
import numpy as np
from datetime import timedelta,datetime

from HelperFunctions.StructureData import structureDataEntropyNumpyArrays, structureDataTelemetryLabels

'''
    Detect anomalies based on a random forest classifier
    Input:  
            trainingSet:    pandas dataframe, training data set
            testingSet:     pandas dataframe, testing data set
            systemId:       string, name of the system to collect and calculate on  
            interval:       timedelta object, size of the sliding window which the calculation is made on
            attackDate:     string, date of the attack the calculations are made on
'''
def calculationsRandomForestTelemetryCombined(systemId, interval, attackDate):
    p = Path('Calculations')
    q = p / 'RandomForest' / 'Telemetry'
    if not q.exists():
        q.mkdir(parents=True)
    f = open(str(q) + "/Alerts.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #f_not = open(str(q) + "/NotAlerts.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    if systemId != "hoytek-gw2" and systemId != "narvik-gw4":
        f.write("sTime,eTime,egress_queue_info__0__cur_buffer_occupancy,egress_stats__if_1sec_pkts,egress_stats__if_1sec_octets,ingress_stats__if_1sec_pkts,ingress_stats__if_1sec_octets,entropy_packet_size_ingress,entropy_rate_packet_size_ingress,entropy_packet_size_egress,entropy_rate_packet_size_egress,real_label")
    else:
        f.write("sTime,eTime,egress_stats__if_1sec_pkts,egress_stats__if_1sec_octets,ingress_stats__if_1sec_pkts,ingress_stats__if_1sec_octets,entropy_packet_size_ingress,entropy_rate_packet_size_ingress,entropy_packet_size_egress,entropy_rate_packet_size_egress,real_label")
    #f_not.write("sTime,eTime,egress_queue_info__0__cur_buffer_occupancy,egress_stats__if_1sec_pkt,ingress_stats__if_1sec_pkt,egress_stats__if_1sec_octet,ingress_stats__if_1sec_octet,entropy_packet_size,entropy_rate_packet_size,real_label")
    f_scores = open(str(q) + "/Score.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_scores.write("confusion_matrix,accuracy,f1,recall,precision")

    datasetsPath = Path('Telemetry')
    dsPath = datasetsPath / 'RandomForest' / 'DataSets'
    with open(str(dsPath) + "/Training/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy", 'rb') as trainingFile:
        trainingSet = np.load(trainingFile, allow_pickle=True)
    with open(str(dsPath) + "/Testing/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy", 'rb') as testingFile:
        testingSet = np.load(testingFile, allow_pickle=True)
    if len(trainingSet) ==0:
        return 
    if len(testingSet) ==0:
        return 
    trainingTimestamps, trainingMeasurements, trainingLabel = structureDataEntropyNumpyArrays(trainingSet) 
    trainingLabel=trainingLabel.astype('int')  

    timeStamps, testingMeasurements, testingLabel = structureDataEntropyNumpyArrays(testingSet)
    testingLabel=testingLabel.astype('int')  

    #Initialize a RF classifier and fit it to the training data set
    classifier_RF = RandomForestClassifier(n_estimators = 100)
    classifier_RF.fit(trainingMeasurements, trainingLabel)


    #Predict the label of the testing data set
    predictions = classifier_RF.predict(testingMeasurements)
    for i in range(len(predictions)):
        line = "\n"  + (timeStamps[i]- timedelta(seconds=2)).strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeStamps[i].strftime("%Y-%m-%dT%H:%M:%SZ")
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