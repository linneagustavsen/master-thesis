from pathlib import Path
from sklearn.cluster import KMeans
import pandas as pd
from HelperFunctions.GetData import *
from HelperFunctions.SimulateRealTime import simulateRealTime
from HelperFunctions.StructureData import *
from HelperFunctions.StructureData import *
from HelperFunctions.ClusterLabelling import labelCluster
import paho.mqtt.client as mqtt
import json

'''
    Do K-means clustering on entropy and field data and write clusters to file
    Input:  
            testingSet: pandas dataframe, data set to detect on
            systemId:   string, name of the system to collect and calculate on
            interval:   timedelta object, size of the sliding window which the calculation is made on
            attackDate: string, date of the attack the calculations are made on
'''
def detectionKmeansCombined(start, stop, systemId, interval, clusterFrequency, DBthreshold, c0threshold, c1threshold, attackDate):
    p = Path('Detections')
    q = p / 'Kmeans' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'kMeansCombinedDetectionNetFlow'
    MQTT_PASSWORD = 'kmeansCombinedDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print(systemId, "Kmeans combined detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("KMeansCombinedDetectionNetFlow")
    #mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
    mqtt_client.loop_start()

    truePositives = 0
    falsePositives = 0
    falseNegatives = 0
    trueNegatives  = 0

    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    intervalTime = (stopTime - startTime).total_seconds()/clusterFrequency.total_seconds()

    srcPortsCluster = []
    dstPortsCluster = []
    protocolCluster = []

    sTimeCluster = []

    eTimeCluster = []

    real_labels = []

    attackTypes = []

    #Loop for every minute in a week
    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + clusterFrequency
        attackCluster = pd.read_csv("Calculations0803/Kmeans/NetFlow/Combined.ClusterLabelling."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime." + stopTime.strftime("%H.%M.%S")+ "."+ str(systemId)+ ".csv")
        if len(attackCluster) == 0:
            continue
        if attackCluster["AttackCluster"][0] == 0:
            cluster = pd.read_csv("Calculations0803/Kmeans/NetFlow/Combined.Cluster0."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime." + stopTime.strftime("%H.%M.%S")+ "."+ str(systemId)+ ".csv")
            attackClusterDiameter = attackCluster["ClusterDiameter0"][0]
            nonAttackClusterDiameter = attackCluster["ClusterDiameter1"][0]

            nonAttackCluster = pd.read_csv("Calculations0803/Kmeans/NetFlow/Combined.Cluster1."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime." + stopTime.strftime("%H.%M.%S")+ "."+ str(systemId)+ ".csv")
        
        elif attackCluster["AttackCluster"][0] == 1:
            cluster = pd.read_csv("Calculations0803/Kmeans/NetFlow/Combined.Cluster1."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime." + stopTime.strftime("%H.%M.%S")+ "."+ str(systemId)+ ".csv")
            attackClusterDiameter =  attackCluster["ClusterDiameter1"][0]
            nonAttackClusterDiameter = attackCluster["ClusterDiameter0"][0]

            nonAttackCluster = pd.read_csv("Calculations0803/Kmeans/NetFlow/Combined.Cluster0."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime." + stopTime.strftime("%H.%M.%S")+ "."+ str(systemId)+ ".csv")
        
        labelsForNonAttackCluster = nonAttackCluster["real_label"]

        for label in labelsForNonAttackCluster:
            if label == 0:
                trueNegatives += 1
            elif label == 1:
                falseNegatives += 1
        
        sTime = pd.to_datetime(cluster["sTime"])
        eTime = pd.to_datetime(cluster["eTime"])

        srcPort = cluster["srcPort"]
        dstPort = cluster["dstPort"]
        protocol = cluster["protocol"]

        labels = cluster["real_label"]

        db = attackCluster["Davies-bouldin-score"][0]
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
        
        attackTypes.append(attackType)
    
        sTimeCluster.extend(sTime)
        eTimeCluster.extend(eTime)
        srcPortsCluster.extend(srcPort)
        dstPortsCluster.extend(dstPort)
        protocolCluster.extend(protocol)
        real_labels.extend(labels)

        startTime += clusterFrequency


    counter = 0
    for i in range(len(sTimeCluster)):
        sTimeCluster[i] = sTimeCluster[i].replace(tzinfo=None)
        eTimeCluster[i] = eTimeCluster[i].replace(tzinfo=None)
        if eTimeCluster[i] > stopTime:
            break
        if sTimeCluster[i] < startTime:
            continue
        simulateRealTime(datetime.now(), sTimeCluster[i], attackDate)
        attackType = ""
        if sTimeCluster[i] < startTime + clusterFrequency:
            attackType = attackTypes[counter]
        if sTimeCluster[i] > startTime + clusterFrequency:
            counter += 1
            attackType = attackTypes[counter]
            startTime += clusterFrequency
        alert = {
                    "sTime": sTimeCluster[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTimeCluster[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "srcPort": int(srcPortsCluster[i]),
                    "dstPort": int(dstPortsCluster[i]),
                    "Protocol": int(protocolCluster[i]),
                    "Deviation_score": None,
                    "Real_label": int(real_labels[i]),
                    "Attack_type": attackType
                }
        '''alert = {
                    "sTime": sTimeCluster[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTimeCluster[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "srcIP":measurements[i][0],
                    "dstIP": measurements[i][1],
                    "srcPort": srcPortsCluster[i],
                    "dstPort": dstPortsCluster[i],
                    "Protocol": protocolCluster[i],
                    "Deviation_score": None,
                    "Real_label": int(real_labels[i]),
                    "Attack_type": attackType
                }'''
        mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

        if real_labels[i]:
            truePositives += 1
        elif not real_labels[i]:
            falsePositives += 1
    scores = open(str(q) + "/Scores.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    scores.write("TP,FP,FN,TN")
    scores.write("\n"+ str(truePositives)+ "," + str(falsePositives)+ "," + str(falseNegatives)+ "," + str(trueNegatives))
    scores.close()