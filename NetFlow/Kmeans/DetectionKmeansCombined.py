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
def detectionKmeansCombined(testingSet, systemId, interval, DBthreshold, c0threshold, c1threshold, attackDate):
    p = Path('Detections')
    q = p / 'Kmeans' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    TPf0 = open(str(q) + "/TP.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TPf0.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets,packet_size_entropy,packet_size_entropy_rate,number_of_packets,number_of_bytes,real_label")
    
    FPf0 = open(str(q) + "/FP.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FPf0.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets,packet_size_entropy,packet_size_entropy_rate,number_of_packets,number_of_bytes,real_label")

    FNf0 = open(str(q) + "/FN.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FNf0.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets,packet_size_entropy,packet_size_entropy_rate,number_of_packets,number_of_bytes,real_label")

    TNf0 = open(str(q) + "/TN.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TNf0.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets,packet_size_entropy,packet_size_entropy_rate,number_of_packets,number_of_bytes,real_label")

    cluster = open(str(q) + "/Combined.ClusterLabelling."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    cluster.write("AttackCluster,Davies-bouldin-score,ClusterDiameter0,ClusterDiameter1,ClusterSize0,ClusterSize1")

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
        print("Kmeans combined detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("KMeansCombinedDetectionNetFlow")
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)

    sTime, eTime, measurements = structureData(testingSet)
    measurements = measurements[:, :-1]
    label = measurements[:,-1]
    sTime = pd.to_datetime(sTime)
    eTime = pd.to_datetime(eTime)

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
        simulateRealTime(datetime.now(), eTime[i], attackDate)      
        if prediction[i] == attackCluster:
            alert = {
                        "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "srcIP":measurements[i][0],
                        "dstIP": measurements[i][1],
                        "srcPort": measurements[i][2],
                        "dstPort": measurements[i][3],
                        "protocol": measurements[i][4],
                        "Value": measurements[i].tolist(),
                        "Real_label": label[i],
                        "Attack_type": attackType
                    }
            mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
    
        line = "\n"  + sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ") + "," + eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")
        for j in range(len(measurements[i])):
            #Skip the IP fields
            if j == 0 or j == 1 or j == 16:
                continue
            line += "," + str(measurements[i][j])
        line += "," +str(label[i])
        if prediction[i] == attackCluster and label[i]:
            TPf0.write(line)
        elif prediction[i] == attackCluster and not label[i]:
            FPf0.write(line)
        elif prediction[i] != attackCluster and label[i]:
            FNf0.write(line)
        elif prediction[i] != attackCluster and not label[i]:
            TNf0.write(line)
    
    TPf0.close()
    FPf0.close()
    FNf0.close()
    TNf0.close()
    cluster.close()



baseFile="two-hours-2011-02-08_10-12-sorted.rw"         
systemId = "oslo-gw1"
start = "2011-02-08 10:00:00"
stop = "2011-02-08 12:00:00"
startCombined = "2011-02-08 10:00:00"
stopCombined = "2011-02-08 12:00:00"
frequency = timedelta(minutes = 1)
interval = timedelta(minutes = 10)
pathToRawFiles="/home/linneafg/silk-data/RawDataFromFilter/"
attackDate="08.02.11"
silkFile = pathToRawFiles+systemId + "/"+ baseFile
windowSize = 10
p = Path('NetFlow')
q = p / 'Kmeans' / 'DataSets'
if not q.exists():
    q = Path('Kmeans')
    q = q / 'DataSets'
testingPath = q / 'Testing'

testingSet = pd.read_pickle(str(testingPath) + "/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")

detectionKmeansCombined(testingSet, systemId, interval, 0.5, 0, 0, attackDate)