from pathlib import Path
from sklearn.cluster import KMeans
import pandas as pd
from HelperFunctionsTelemetry.GetDataTelemetry import *
from HelperFunctions.StructureData import *
from HelperFunctions.IsAttack import *
from datetime import datetime
import json
import paho.mqtt.client as mqtt

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
def detectionKmeansEntropyTelemetry(start, stop, systemId, if_name, interval, frequency, DBthreshold, c0threshold, c1threshold, attackDate):
    p = Path('Detections')
    q = p / 'Kmeans' / 'Telemetry'
    if not q.exists():
        q.mkdir(parents=True)

    TPf0 = open(str(q) + "/TP.Entropy.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TPf0.write("sTime,eTime,entropy_packet_size,entropy_rate_packet_size,real_label")

    FPf0 = open(str(q) + "/FP.Entropy.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FPf0.write("sTime,eTime,entropy_packet_size,entropy_rate_packet_size,real_label")

    FNf0 = open(str(q) + "/FN.Entropy.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FNf0.write("sTime,eTime,entropy_packet_size,entropy_rate_packet_size,real_label")

    TNf0 = open(str(q) + "/TN.Entropy.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TNf0.write("sTime,eTime,entropy_packet_size,entropy_rate_packet_size,real_label")

    cluster = open(str(q) + "/Entropy.ClusterLabelling.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    cluster.write("AttackCluster,Davies-bouldin-score,ClusterDiameter0,ClusterDiameter1,ClusterSize0,ClusterSize1")
    
    #Parameters for the MQTT connection
    MQTT_BROKER = 'mosquitto'
    MQTT_PORT = 1883
    MQTT_USER = 'kMeansEntropyDetectionTelemetry'
    MQTT_PASSWORD = 'kMeansEntropyDetectionPass'
    MQTT_TOPIC = 'detections/modules/telemetry'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("K-means entropy detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("KmeansEntropyDetectionTelemetry")
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)

    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    df = getEntropyData(startTime, stopTime, systemId, if_name, interval, frequency)
    #df.to_pickle("NetFlow/Kmeans/RawData/Testing.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    #df = pd.read_pickle("NetFlow/Kmeans/RawData/Testing.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    timeStamps, measurements = structureDataTelemetry(df)
    timeStamps = pd.to_datetime(timeStamps)

    prediction = KMeans(n_clusters=2, random_state=0, n_init="auto").fit_predict(measurements)
    attackCluster, db, cd0, cd1, counter0, counter1 = labelCluster(measurements, prediction, DBthreshold, c0threshold, c1threshold)
    cluster.write("\n"+ str(attackCluster) + "," + str(db) + "," + str(cd0) + "," + str(cd1)+ "," + str(counter0)+ "," + str(counter1))

    attackType = ""
    #If it is a burst attack and cluster 1 is very compact, it is the attack cluster
    if db == 0 and cd1 == 0:
        attackType = "Same protocol"
    #If there is no burst and c0 is less compact than c1, c1 is the attack cluster
    elif db > DBthreshold and cd0 > (cd1 + c0threshold):
        attackType = "Different protocols"
    #If there is burst traffic and normal traffic and c1 is less compact than c0, c1 is the attack cluster
    elif db < DBthreshold and cd1 > (cd0 + c1threshold):
        attackType = "Same protocol"

    for i in range(len(prediction)):
        attack = isAttack(timeStamps[i]+ interval - frequency, timeStamps[i]+ interval)
        if prediction[i] == attackCluster:
            alert = {
                        "sTime": (timeStamps[i]+ interval - frequency).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": (timeStamps[i]+ interval).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "Value": measurements[i],
                        "Real_label": int(attack),
                        "Attack_type": attackType
                    }
            mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

        line = "\n"  + (timeStamps[i]+ interval - frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," + (timeStamps[i]+ interval).strftime("%Y-%m-%dT%H:%M:%SZ")
        for measurement in measurements[i]:
            line += "," + str(measurement)
        line += "," +str(int(attack))
        if prediction[i] == attackCluster and attack:
            TPf0.write(line)
        elif prediction[i] == attackCluster and not attack:
            FPf0.write(line)
        elif prediction[i] != attackCluster and attack:
            FNf0.write(line)
        elif prediction[i] != attackCluster and not attack:
            TNf0.write(line)
    
    TPf0.close()
    FPf0.close()
    FNf0.close()
    TNf0.close()
    cluster.close()
'''start = "2022-09-21 01:00:00"
stop = "2022-09-22 00:00:00"
systemId = "trd-gw"
if_name = "xe-0/1/0"
interval = timedelta(minutes = 5)
frequency = timedelta(minutes = 1)
attackDate = "21.09"
detectionKmeansEntropyTelemetry(start, stop, systemId, if_name, interval, frequency, attackDate)'''