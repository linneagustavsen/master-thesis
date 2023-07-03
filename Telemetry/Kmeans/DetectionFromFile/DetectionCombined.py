from pathlib import Path
from sklearn.cluster import KMeans
import pandas as pd
from HelperFunctions.GetData import *
from HelperFunctions.SimulateRealTime import simulateRealTime
from HelperFunctions.StructureData import *
from datetime import datetime,timedelta
from HelperFunctions.IsAttack import *
from Telemetry.Kmeans.ClusterLabelling import labelCluster
import json
import paho.mqtt.client as mqtt
from time import sleep
from random import randrange
from HelperFunctions.AttackIntervals import inAttackInterval

'''
    Do K-means clustering on entropy data and field data and write both clusters to file
    Input:  testingSet: pandas dataframe, data set to detect anomalies on
            systemId:   string, name of the system to collect and calculate on  
            if_name:    string, interface name
            interval:   timedelta object, size of the sliding window which the calculation is made on,
            attackDate: string, date of the attack the calculations are made on
'''
def detectionKmeansCombinedTelemetry(start, stop, systemId, interval, clusterFrequency, DBthreshold, c0threshold, c1threshold, weight, attackDate):

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'kMeansCombinedDetectionTelemetry'
    MQTT_PASSWORD = 'kMeansCombinedDetectionPass'
    MQTT_TOPIC = 'detections/modules/telemetry'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        s=0
        #print(systemId, "Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print(systemId, "K-means combined detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("KmeansCombinedDetectionTelemetry")
    #mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
    #mqtt_client.loop_start()

    if attackDate == "08.03.23":
        fileString = "0803"
        attackDict = {"SYN Flood":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "SlowLoris": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "Ping Flood": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "R.U.D.Y":{"TP":0, "FP":0, "TN": 0, "FN": 0}}
    elif attackDate == "17.03.23":
        fileString = "1703"
        attackDict = {"SYN Flood":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "SlowLoris": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "Ping Flood": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "R.U.D.Y":{"TP":0, "FP":0, "TN": 0, "FN": 0}}
    elif attackDate == "24.03.23":
        fileString = "2403"
        attackDict = {"UDP Flood":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "SlowLoris": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "Ping Flood": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "Slow Read":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "Blacknurse":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "SYN Flood":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "R.U.D.Y":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "Xmas":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "UDP Flood and SlowLoris":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "Ping Flood and R.U.D.Y":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "All types":{"TP":0, "FP":0, "TN": 0, "FN": 0}}
    truePositives = 0
    falsePositives = 0
    falseNegatives = 0
    trueNegatives  = 0

    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    intervalTime = (stopTime - startTime).total_seconds()/clusterFrequency.total_seconds()

    sTimeCluster = []

    eTimeCluster = []

    real_labels = []

    #attackTypes = []

    #Loop for every minute in a week
    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + clusterFrequency
        attackCluster = pd.read_csv("Calculations"+fileString+"/Kmeans/Telemetry/Combined.ClusterLabelling."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime." + stopTime.strftime("%H.%M.%S")+ "."+ str(systemId)+ ".csv")
        if attackCluster.empty:
            continue
        if attackCluster["AttackCluster"][0] == 0:
            clusterFile = "Calculations"+fileString+"/Kmeans/Telemetry/Combined.Cluster0."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime." + stopTime.strftime("%H.%M.%S")+ "."+ str(systemId)+ ".csv"
            '''attackClusterDiameter = attackCluster["ClusterDiameter0"][0]
            nonAttackClusterDiameter = attackCluster["ClusterDiameter1"][0]'''

            nonAttackCluster = pd.read_csv("Calculations"+fileString+"/Kmeans/Telemetry/Combined.Cluster1."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime." + stopTime.strftime("%H.%M.%S")+ "."+ str(systemId)+ ".csv")
        
        elif attackCluster["AttackCluster"][0] == 1:
            clusterFile = "Calculations"+fileString+"/Kmeans/Telemetry/Combined.Cluster1."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime." + stopTime.strftime("%H.%M.%S")+ "."+ str(systemId)+ ".csv"
            '''attackClusterDiameter =  attackCluster["ClusterDiameter1"][0]
            nonAttackClusterDiameter = attackCluster["ClusterDiameter0"][0]'''

            nonAttackCluster = pd.read_csv("Calculations"+fileString+"/Kmeans/Telemetry/Combined.Cluster0."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime." + stopTime.strftime("%H.%M.%S")+ "."+ str(systemId)+ ".csv")
        
        nonAttackCluster_sTime = pd.to_datetime(nonAttackCluster["sTime"])
        nonAttackCluster_eTime = pd.to_datetime(nonAttackCluster["eTime"])
        labelsForNonAttackCluster = nonAttackCluster["real_label"]
        
        for k in range(len(labelsForNonAttackCluster)):
            isInAttackTime, attackTypeDuringThisTime = inAttackInterval(nonAttackCluster_sTime[k], nonAttackCluster_eTime[k], attackDate)
            if labelsForNonAttackCluster[k] == 0:
                trueNegatives += 1
                if isInAttackTime:
                    attackDict[attackTypeDuringThisTime]["TN"] += 1

            elif labelsForNonAttackCluster[k] == 1:
                falseNegatives += 1 
                if isInAttackTime:
                    attackDict[attackTypeDuringThisTime]["FN"] += 1   
        del nonAttackCluster
        del labelsForNonAttackCluster
        del nonAttackCluster_sTime
        del nonAttackCluster_eTime
        
        counter = 0
        countClusters = 0
        for cluster in pd.read_csv(clusterFile, chunksize=100):
            countClusters += 1
            sTimeCluster = pd.to_datetime(cluster["sTime"])
            eTimeCluster = pd.to_datetime(cluster["eTime"])
            cluster = cluster.dropna()

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
                attackType = "Same protocol"
            
            attackTypes.append(attackType)'''

            starting = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
            stopping = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
            for i in range(len(sTimeCluster)):
                isInAttackTime, attackTypeDuringThisTime = inAttackInterval(sTimeCluster[counter], eTimeCluster[counter], attackDate)
                sTimeCluster[counter] = sTimeCluster[counter].replace(tzinfo=None)
                eTimeCluster[counter] = eTimeCluster[counter].replace(tzinfo=None)
                if eTimeCluster[counter] > stopping:
                    break
                if sTimeCluster[counter] < starting:
                    counter += 1
                    continue

                if real_labels[counter] == np.nan or real_labels[counter] == None:
                    attack = None
                else:
                    attack = int(real_labels[counter])
                
                '''attackType = ""
                if sTimeCluster[counter] < startTime + clusterFrequency:
                    attackType = attackTypes[counter]
                if sTimeCluster[counter] > startTime + clusterFrequency:
                    counter += 1
                    attackType = attackTypes[counter]
                    startTime += clusterFrequency'''
                #simulateRealTime(datetime.now(), eTimeCluster[counter], attackDate)
                alert = {
                            "sTime": sTimeCluster[counter].strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "eTime": eTimeCluster[counter].strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "Gateway": systemId,
                            "Deviation_score": None,
                            "Real_label": attack,
                            "Attack_type": "",
                            "Weight": weight
                        }
                #mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

                if real_labels[counter]:
                    truePositives += 1
                    if isInAttackTime:
                        attackDict[attackTypeDuringThisTime]["TP"] += 1
                elif not real_labels[counter]:
                    falsePositives += 1
                    if isInAttackTime:
                        attackDict[attackTypeDuringThisTime]["FP"] += 1
                counter += 1
            counter = 100*countClusters
        startTime += clusterFrequency
    #sleep(randrange(400))
    p = Path('Detections' + fileString)
    q = p / 'Kmeans' / 'Telemetry'
    if not q.exists():
        q.mkdir(parents=True)

    scores = open(str(q) + "/Scores.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    scores.write("TP,FP,FN,TN")
    scores.write("\n"+ str(truePositives)+ "," + str(falsePositives)+ "," + str(falseNegatives)+ "," + str(trueNegatives))
    scores.close()


    attackScores = open(str(q) + "/ScoresAttacks.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json", "w")
    json.dump(attackDict,attackScores)
    attackScores.close()