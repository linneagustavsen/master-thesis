from pathlib import Path
from sklearn.cluster import KMeans
import pandas as pd
from HelperFunctionsTelemetry.GetDataTelemetry import *
from HelperFunctions.StructureData import *
from datetime import datetime,timedelta
from HelperFunctions.IsAttack import *
from Telemetry.Kmeans.ClusterLabelling import labelCluster
import json
import paho.mqtt.client as mqtt

'''
    Do K-means clustering on field data write both clusters to file
    Input:  start:      string, indicating the start time of the data to detect on
            stop:       string, indicating the stop time of the data to detect on
            systemId:   string, name of the system to collect and calculate on  
            if_name:    string, interface name 
            fields:     list of strings, features to incorporate in the clustering
            attackDate: string, date of the attack the calculations are made on
'''
def detectionKmeansTelemetry(start, stop, systemId, if_name, fields, DBthreshold, c0threshold, c1threshold, attackDate):
    p = Path('Detections')
    q = p / 'Kmeans' / 'Telemetry'
    if not q.exists():
        q.mkdir(parents=True)

    TPf0 = open(str(q) + "/TP.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TPf0.write("sTime,eTime,egress_queue_info__0__cur_buffer_occupancy,egress_stats__if_1sec_pkt,ingress_stats__if_1sec_pkt,egress_stats__if_1sec_octet,ingress_stats__if_1sec_octet,real_label")

    FPf0 = open(str(q) + "/FP.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FPf0.write("sTime,eTime,egress_queue_info__0__cur_buffer_occupancy,egress_stats__if_1sec_pkt,ingress_stats__if_1sec_pkt,egress_stats__if_1sec_octet,ingress_stats__if_1sec_octet,real_label")

    FNf0 = open(str(q) + "/FN.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FNf0.write("sTime,eTime,egress_queue_info__0__cur_buffer_occupancy,egress_stats__if_1sec_pkt,ingress_stats__if_1sec_pkt,egress_stats__if_1sec_octet,ingress_stats__if_1sec_octet,real_label")

    TNf0 = open(str(q) + "/TN.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TNf0.write("sTime,eTime,egress_queue_info__0__cur_buffer_occupancy,egress_stats__if_1sec_pkt,ingress_stats__if_1sec_pkt,egress_stats__if_1sec_octet,ingress_stats__if_1sec_octet,real_label")

    cluster = open(str(q) + "/ClusterLabelling.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    cluster.write("AttackCluster,Davies-bouldin-score,ClusterDiameter0,ClusterDiameter1,ClusterSize0,ClusterSize1")
    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'kMeanDetectionTelemetry'
    MQTT_PASSWORD = 'kMeansDetectionPass'
    MQTT_TOPIC = 'detections/modules/telemetry'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("Kmeans detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("KmeansDetectionTelemetry")
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)

    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    df = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), systemId, if_name, fields)
    
    '''p = Path('NetFlow')
    q = p / 'Kmeans' / 'RawData'
    if not q.exists():
        q.mkdir(parents=True)'''
    #df.to_pickle(str(q) + "Testing.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    #df = pd.read_pickle(str(q) + "Testing.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    timeStamps, measurements = structureDataTelemetry(df)
    
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
        attack = isAttack(timeStamps[i] -timedelta(seconds = 2), timeStamps[i])
        if prediction[i] == attackCluster: 
            alert = {
                        "sTime": (timeStamps[i] - timedelta(seconds = 2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": timeStamps[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "Deviation_score": None,
                        #"Value": measurements[i],
                        "Real_label": int(attack),
                        "Attack_type": attackType
                    }
            mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

        line = "\n"  + (timeStamps[i] - timedelta(seconds = 2)).strftime("%Y-%m-%dT%H:%M:%SZ") + timeStamps[i].strftime("%Y-%m-%dT%H:%M:%SZ")
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
fields = ["egress_queue_info__0__avg_buffer_occupancy", "egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets"]

detectionKmeansTelemetry(start, stop, systemId, if_name, fields, attackDate)'''