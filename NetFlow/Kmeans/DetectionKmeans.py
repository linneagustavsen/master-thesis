from pathlib import Path
from sklearn.cluster import KMeans
from HelperFunctions.GetData import *
from silk import *
from HelperFunctions.SimulateRealTime import simulateRealTime
from HelperFunctions.StructureData import *
from HelperFunctions.ClusterLabelling import labelCluster
import paho.mqtt.client as mqtt
import json

'''
    Do K-means clustering on fields and write clusters to file
    Input:  
            silkFile:   string, file with flow records sorted on time
            start:      string, indicating the start time of the data wanted
            stop:       string, indicating the stop time of the data wanted
            systemId:   string, name of the system to collect and detect on
            attackDate: string, date of the attack the detections are made on
'''
def detectionKmeans(silkFile, start, stop, systemId, DBthreshold, c0threshold, c1threshold, attackDate):
    p = Path('Detections')
    q = p / 'Kmeans' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    TPf0 = open(str(q) + "/TP.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TPf0.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,real_label")

    FPf0 = open(str(q) + "/FP.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FPf0.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,real_label")

    FNf0 = open(str(q) + "/FN.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FNf0.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,real_label")

    TNf0 = open(str(q) + "/TN.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TNf0.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,real_label")

    cluster = open(str(q) + "/ClusterLabelling.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    cluster.write("AttackCluster,Davies-Bouldin-score,ClusterDiameter0,ClusterDiameter1,ClusterSize0,ClusterSize1")

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'kMeansDetectionNetFlow'
    MQTT_PASSWORD = 'kmeansDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("Kmeans detection is published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("KMeansDetectionNetFlow")
    #mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
    mqtt_client.loop_start()

    testingData = getDataNetFlow(silkFile, start, stop)
    sTime, eTime, measurements = structureData(testingData)
    measurements = measurements[:, :-1]
    label = measurements[:,-1]
    sTime = pd.to_datetime(sTime)
    eTime = pd.to_datetime(eTime)
    prediction = KMeans(n_clusters=2, random_state=0, n_init="auto").fit_predict(measurements)
    attackCluster, db, cd0, cd1, counter0, counter1 = labelCluster(measurements, prediction, DBthreshold, c0threshold, c1threshold)
    cluster.write("\n"+ str(attackCluster) + "," + str(db) + "," + str(cd0) + "," + str(cd1)+ "," + str(counter0)+ "," + str(counter1))

    if attackCluster == 0:
        attackClusterDiameter = cd0
        nonAttackClusterDiameter = cd1
    elif attackCluster == 1:
        attackClusterDiameter = cd1
        nonAttackClusterDiameter = cd0
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
   
    for i in range(len(prediction)):
        simulateRealTime(datetime.now(), sTime[i], attackDate)
        if prediction[i] == attackCluster:
            alert = {
                        "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "srcIP":measurements[i][0],
                        "dstIP": measurements[i][1],
                        "srcPort": measurements[i][2],
                        "dstPort": measurements[i][3],
                        "Protocol": measurements[i][4],
                        "Deviation_score": None,
                        '''"Value": measurements[i].tolist(),
                        "Real_label": label[i],'''
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

detectionKmeans(silkFile, start, stop, systemId, 0.5, 0, 0, attackDate)