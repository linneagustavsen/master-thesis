from pathlib import Path
from sklearn.cluster import KMeans
from HelperFunctions.GetData import *
from HelperFunctions.SimulateRealTime import simulateRealTime
from HelperFunctions.StructureData import *
from HelperFunctions.ClusterLabelling import labelCluster
import paho.mqtt.client as mqtt
import json

'''
    Do K-means clustering on entropy data and write clusters to file
    Input:  silkFile:   string, file with flow records sorted on time
            start:      string, indicating the start time of the data wanted
            stop:       string, indicating the stop time of the data wanted
            systemId:   string, name of the system to collect and calculate on
            frequency:  timedelta object, frequency of metric calculation
            interval:   timedelta object, size of the sliding window which the calculation is made on
            attackDate: string, date of the attack the calculations are made on
'''
def detectionKmeansEntropy(start, stop, systemId, interval, DBthreshold, c0threshold, c1threshold, attackDate):
    p = Path('Detections')
    q = p / 'Kmeans' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    scores = open(str(q) + "/Scores.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    scores.write("TP,FP,FN,TN")

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'kMeansEntropyDetectionNetFlow'
    MQTT_PASSWORD = 'kmeansEntropyDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print(systemId, "Kmeans entropy detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("KMeansEntropyDetectionNetFlow")
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)

    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    truePositives = 0
    falsePositives = 0
    falseNegatives = 0
    trueNegatives  = 0

    attackCluster = pd.read_csv("Calculations0803/Kmeans/NetFlow/Entropy.ClusterLabelling."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
    if len(attackCluster) == 0:
        return
    if attackCluster["AttackCluster"][0] == 0:
        cluster = pd.read_csv("Calculations0803/Kmeans/NetFlow/Entropy.Cluster0."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
        attackClusterDiameter = attackCluster["ClusterDiameter0"][0]
        nonAttackClusterDiameter = attackCluster["ClusterDiameter1"][0]

        nonAttackCluster = pd.read_csv("Calculations0803/Kmeans/NetFlow/Entropy.Cluster1."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
    
    elif attackCluster["AttackCluster"][0] == 1:
        cluster = pd.read_csv("Calculations0803/Kmeans/NetFlow/Entropy.Cluster1."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
        attackClusterDiameter =  attackCluster["ClusterDiameter1"][0]
        nonAttackClusterDiameter = attackCluster["ClusterDiameter0"][0]

        nonAttackCluster = pd.read_csv("Calculations0803/Kmeans/NetFlow/Entropy.Cluster0."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
    
    labelsForNonAttackCluster = nonAttackCluster["real_label"]

    for label in labelsForNonAttackCluster:
        if label == 0:
            trueNegatives += 1
        elif label == 1:
            falseNegatives += 1
    
    sTime = pd.to_datetime(cluster["sTime"])
    eTime = pd.to_datetime(cluster["eTime"])

    real_labels = cluster["real_label"]

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
        
    for i in range(len(sTime)):
        sTime[i] = sTime[i].replace(tzinfo=None)
        eTime[i] = eTime[i].replace(tzinfo=None)
        if eTime[i] > stopTime:
            break
        if sTime[i] < startTime:
            continue
        simulateRealTime(datetime.now(), eTime[i], attackDate)
        
        alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": None,
                    "Real_label": int(real_labels[i]),
                    "Attack_type": attackType
                }
        mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
        
        if real_labels[i]:
            truePositives += 1
        elif not real_labels[i]:
            falsePositives += 1
    
    scores.write("\n"+ str(truePositives)+ "," + str(falsePositives)+ "," + str(falseNegatives)+ "," + str(trueNegatives))
    scores.close()