from pathlib import Path
from sklearn.cluster import KMeans
from HelperFunctions.GetData import *
from HelperFunctions.SimulateRealTime import simulateRealTime
from HelperFunctions.StructureData import *
from HelperFunctions.ClusterLabelling import labelCluster
import paho.mqtt.client as mqtt
from time import sleep
from random import randrange
from HelperFunctions.AttackIntervals import inAttackInterval
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
def detectionKmeansEntropy(start, stop, systemId, interval, DBthreshold, c0threshold, c1threshold, weight, attackDate):
    

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'kMeansEntropyDetectionNetFlow'
    MQTT_PASSWORD = 'kmeansEntropyDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        s=0
        #print(systemId, "Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        s=0
        #print(systemId, "Kmeans entropy detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("KMeansEntropyDetectionNetFlow")
    #mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
    mqtt_client.loop_start()

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
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    truePositives = 0
    falsePositives = 0
    falseNegatives = 0
    trueNegatives  = 0

    attackCluster = pd.read_csv("Calculations"+fileString+"/Kmeans/NetFlow/Entropy.ClusterLabelling."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
    if len(attackCluster) == 0:
        return
    if fileString == "0803":
        if attackCluster["AttackCluster"][0] == 0:
            cluster = pd.read_csv("Calculations"+fileString+"/Kmeans/NetFlow/Entropy.Cluster0."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
            attackClusterDiameter = attackCluster["ClusterDiameter0"][0]
            nonAttackClusterDiameter = attackCluster["ClusterDiameter1"][0]

            nonAttackCluster = pd.read_csv("Calculations"+fileString+"/Kmeans/NetFlow/Entropy.Cluster1."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
        
        elif attackCluster["AttackCluster"][0] == 1:
            cluster = pd.read_csv("Calculations"+fileString+"/Kmeans/NetFlow/Entropy.Cluster1."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
            attackClusterDiameter =  attackCluster["ClusterDiameter1"][0]
            nonAttackClusterDiameter = attackCluster["ClusterDiameter0"][0]

            nonAttackCluster = pd.read_csv("Calculations"+fileString+"/Kmeans/NetFlow/Entropy.Cluster0."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
        
        nonAttackCluster_sTime = pd.to_datetime(nonAttackCluster["sTime"])
        nonAttackCluster_eTime = pd.to_datetime(nonAttackCluster["eTime"])
        labelsForNonAttackCluster = nonAttackCluster["real_label"]
        
        for i in range(len(labelsForNonAttackCluster)):
            isInAttackTime, attackTypeDuringThisTime = inAttackInterval(nonAttackCluster_sTime[i], nonAttackCluster_eTime[i], attackDate)
            if labelsForNonAttackCluster[i] == 0:
                trueNegatives += 1
                if isInAttackTime:
                    attackDict[attackTypeDuringThisTime]["TN"] += 1

            elif labelsForNonAttackCluster[i] == 1:
                falseNegatives += 1 
                if isInAttackTime:
                    attackDict[attackTypeDuringThisTime]["FN"] += 1   
    else:
        clusterFile = "Calculations"+fileString+"/Kmeans/NetFlow/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv"
        ''' attackClusterDiameter = attackCluster["ClusterDiameter0"][0]
        nonAttackClusterDiameter = attackCluster["ClusterDiameter1"][0]'''

        scores = pd.read_csv("Calculations"+fileString+"/Kmeans/NetFlow/Scores.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
            
        tn = scores["TN"][0]
        fn = scores["FN"][0]
        trueNegatives += tn
        falseNegatives += fn
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
            isInAttackTime, attackTypeDuringThisTime = inAttackInterval(sTime[counter], eTime[counter], attackDate)
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
                        "Attack_type": "",
                        "Weight": weight
                    }
            mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
            
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
    #sleep(randrange(400))
    p = Path('Detections' + fileString)
    q = p / 'Kmeans' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    scores = open(str(q) + "/Scores.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    scores.write("TP,FP,FN,TN")
    scores.write("\n"+ str(truePositives)+ "," + str(falsePositives)+ "," + str(falseNegatives)+ "," + str(trueNegatives))
    scores.close()

    attackScores = open(str(q) + "/ScoresAttacks.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json", "w")
    json.dump(attackDict,attackScores)
    attackScores.close()