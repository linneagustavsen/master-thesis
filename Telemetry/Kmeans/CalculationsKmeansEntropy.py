from pathlib import Path
from sklearn.cluster import KMeans
from sklearn.metrics import confusion_matrix, f1_score, accuracy_score, recall_score, precision_score
import pandas as pd
from HelperFunctionsTelemetry.GetDataTelemetry import *
from HelperFunctions.StructureData import *
from HelperFunctions.IsAttack import *
from datetime import datetime
import json
import paho.mqtt.client as mqtt
from time import sleep
from random import randrange

from Telemetry.Kmeans.ClusterLabelling import labelCluster

'''
    Do K-means clustering on entropy data and write clusters to file
    Input:  start:      string, indicating the start time of the data to detect on
            stop:       string, indicating the stop time of the data to detect on
            systemId:   string, name of the system to collect and calculate on  
            if_name:    string, interface name, 
            interval:   timedelta object, size of the sliding window which the calculation is made on,
            frequency:  timedelta object, frequency of metric calculation,
            attackDate: string, date of the attack the calculations are made on
'''
def calculationsKmeansEntropyTelemetry(start, stop, systemId, bucket, interval, frequency, attackDate):
    p = Path('Calculations')
    q = p / 'Kmeans' / 'Telemetry'
    if not q.exists():
        q.mkdir(parents=True)

    f0 = open(str(q) + "/Entropy.Cluster0."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f1 = open(str(q) + "/Entropy.Cluster1."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f0.write("sTime,eTime,entropy_packet_size_ingress,entropy_rate_packet_size_ingress,entropy_packet_size_egress,entropy_rate_packet_size_egress,real_label")
    f1.write("sTime,eTime,entropy_packet_size_ingress,entropy_rate_packet_size_ingress,entropy_packet_size_egress,entropy_rate_packet_size_egress,real_label")
    cluster = open(str(q) + "/Entropy.ClusterLabelling."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    cluster.write("AttackCluster,Davies-bouldin-score,ClusterDiameter0,ClusterDiameter1,ClusterSize0,ClusterSize1")
    '''f_scores = open(str(q) + "/Entropy.Score."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_scores.write("confusion_matrix,accuracy,f1,recall,precision")
'''

    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')

    dataPath = Path('Telemetry')
    dp = dataPath /'Kmeans'/ 'DataSets' 

    entropyFile = str(dp) +"/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl"
    if Path(entropyFile).exists():
        with open(str(entropyFile), 'rb') as f:
            df = pd.read_pickle(f)
    else:
        print("Cant find", entropyFile)
        df = getEntropyData(startTime, stopTime, systemId, bucket, interval, frequency)

        if not dp.exists():
            dp.mkdir(parents=True, exist_ok=False)
        with open(str(dp) + "/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl", 'wb') as f:
            df.to_pickle(f)

    if len(df) <2:
        return
    
    timeIntervals, measurements, labels = structureDataEntropy(df)

    prediction = KMeans(n_clusters=2, random_state=0, n_init="auto").fit_predict(measurements)

    attackCluster, db, cd0, cd1, counter0, counter1 = labelCluster(measurements, prediction, 0.5, 0, 0)
    cluster.write("\n"+ str(attackCluster) + "," + str(db) + "," + str(cd0) + "," + str(cd1)+ "," + str(counter0)+ "," + str(counter1))
    for i in range(len(prediction)):
        line = "\n"  + timeIntervals[i].left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," +timeIntervals[i].right.strftime("%Y-%m-%dT%H:%M:%SZ")

        for measurement in measurements[i]:
            line += "," + str(measurement)
        line += "," +str(labels[i])

        if prediction[i] == 0: 
            f0.write(line)
        elif prediction[i] == 1: 
            f1.write(line)

    f0.close()
    f1.close()
    cluster.close()
    '''f_scores.write("\n"+str(confusion_matrix(labels, kmeans.labels_)) + ","+ str(accuracy_score(labels, kmeans.labels_)) + ","+ 
                str(f1_score(labels,kmeans.labels_)) + ","+ str(recall_score(labels,kmeans.labels_)) + ","+ 
                str(precision_score(labels,kmeans.labels_)))
    f_scores.close()'''
