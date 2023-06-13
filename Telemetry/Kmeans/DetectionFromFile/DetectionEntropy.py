from pathlib import Path
from sklearn.cluster import KMeans
import pandas as pd
from HelperFunctions.SimulateRealTime import simulateRealTime
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
def detectionKmeansEntropyTelemetry(start, stop, systemId, interval, DBthreshold, c0threshold, c1threshold, attackDate):

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'kMeansEntropyDetectionTelemetry'
    MQTT_PASSWORD = 'kMeansEntropyDetectionPass'
    MQTT_TOPIC = 'detections/modules/telemetry'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        s=0
        #print(systemId, "Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print(systemId, "K-means entropy detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("KmeansEntropyDetectionTelemetry")
    #mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
    mqtt_client.loop_start()

    if attackDate == "08.03.23":
        fileString = "0803"
    elif attackDate == "17.03.23":
        fileString = "1703"
    elif attackDate == "24.03.23":
        fileString = "2403"
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    
    truePositives = 0
    falsePositives = 0
    falseNegatives = 0
    trueNegatives  = 0

    attackCluster = pd.read_csv("Calculations"+fileString+"/Kmeans/Telemetry/Entropy.ClusterLabelling."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
    if attackCluster.empty:
        return
    if attackCluster["AttackCluster"][0] == 0:
        clusterFile = "Calculations"+fileString+"/Kmeans/Telemetry/Entropy.Cluster0."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv"
        '''attackClusterDiameter = attackCluster["ClusterDiameter0"][0]
        nonAttackClusterDiameter = attackCluster["ClusterDiameter1"][0]'''

        nonAttackCluster = pd.read_csv("Calculations"+fileString+"/Kmeans/Telemetry/Entropy.Cluster1."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
    
    elif attackCluster["AttackCluster"][0] == 1:
        clusterFile = "Calculations"+fileString+"/Kmeans/Telemetry/Entropy.Cluster1."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv"
        '''attackClusterDiameter =  attackCluster["ClusterDiameter1"][0]
        nonAttackClusterDiameter = attackCluster["ClusterDiameter0"][0]'''

        nonAttackCluster = pd.read_csv("Calculations"+fileString+"/Kmeans/Telemetry/Entropy.Cluster0."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
    
    labelsForNonAttackCluster = nonAttackCluster["real_label"]

    for label in labelsForNonAttackCluster:
        if label == 0:
            trueNegatives += 1
        elif label == 1:
            falseNegatives += 1
    
    del nonAttackCluster
    del labelsForNonAttackCluster
    
    counter = 0
    countClusters = 0
    for cluster in pd.read_csv(clusterFile, chunksize=100):
        countClusters += 1
        sTime = pd.to_datetime(cluster["sTime"])
        eTime = pd.to_datetime(cluster["eTime"])

        real_labels = cluster["real_label"]

        '''db = attackCluster["Davies-bouldin-score"][0]
        attackType = ""
        #If it is a burst attack and non attack cluster is empty
        if db < DBthreshold and nonAttackClusterDiameter == 0:
            attackType = "Same protocol"
        #If there is no burst and attack cluster is less compact than normal traffic
        elif db > DBthreshold and attackClusterDiameter > (nonAttackClusterDiameter + c0threshold):
            attackType = "Different protocols"
        #If there is burst traffic and normal traffic and normal traffic is less compact than attack traffic
        elif db < DBthreshold and nonAttackClusterDiameter > (attackClusterDiameter + c1threshold):
            attackType = "Same protocol"'''
            
        for i in range(len(sTime)):
            sTime[counter] = sTime[counter].replace(tzinfo=None)
            eTime[counter] = eTime[counter].replace(tzinfo=None)
            if eTime[counter] > stopTime:
                break
            if sTime[counter] < startTime:
                counter += 1
                continue
            simulateRealTime(datetime.now(), eTime[counter], attackDate)
            
            alert = {
                        "sTime": sTime[counter].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": eTime[counter].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "Deviation_score": None,
                        "Real_label": int(real_labels[counter]),
                        "Attack_type": ""
                    }
            mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

            if real_labels[counter]:
                truePositives += 1
            elif not real_labels[counter]:
                falsePositives += 1
            counter += 1
        counter = 100*countClusters
    sleep(randrange(400))
    p = Path('Detections' + fileString)
    q = p / 'Kmeans' / 'Telemetry'
    if not q.exists():
        q.mkdir(parents=True)

    scores = open(str(q) + "/Scores.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    scores.write("TP,FP,FN,TN")
    scores.write("\n"+ str(truePositives)+ "," + str(falsePositives)+ "," + str(falseNegatives)+ "," + str(trueNegatives))
    scores.close()