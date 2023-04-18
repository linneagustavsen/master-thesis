from sklearn.cluster import KMeans
from HelperFunctions.GetData import *
from silk import *
from HelperFunctions.StructureData import *
from HelperFunctions.IsAttack import *
from NetFlow.Kmeans.ClusterLabelling import labelCluster
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
    f0 = open("Detections/Kmeans/NetFlow/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f0.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,real_label")
    cluster = open("Detections/Kmeans/NetFlow/ClusterLabelling.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    cluster.write("AttackCluster,Davies-Bouldin-score,ClusterDiameter0,ClusterDiameter1,ClusterSize0,ClusterSize1")

    #Parameters for the MQTT connection
    MQTT_BROKER = 'mosquitto'
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
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)

    testingData = getDataNetFlow(silkFile, start, stop)
    sTime, eTime, measurements = structureData(testingData)
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
        if prediction[i] == attackCluster:
            line = "\n"  + sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ") + "," + eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")
            for j in range(len(measurements[i])):
                #Skip the IP fields
                if j == 0 or j == 1 or j == 16:
                    continue
                line += "," + str(measurements[i][j])
            line += "," +str(label[i])
            f0.write(line)
            alert = {
                        "Time": sTime[i],
                        "Gateway": systemId,
                        "Value": measurements[i],
                        "Real_label": label[i],
                        "Attack_type": attackType
                    }
            mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

    f0.close()