from pathlib import Path
import pandas as pd
from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime,timedelta
import json
import paho.mqtt.client as mqtt
from HelperFunctions.IsAttack import isAttack
from HelperFunctions.Normalization import normalization
from HelperFunctions.SimulateRealTime import simulateRealTime


def topkflows(start, stop, systemId, attackDate):

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'topkFlowsDetectionNetFlow'
    MQTT_PASSWORD = 'topKflowsDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print(systemId, "Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        s=0
        #print(systemId, "Top k flows detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("TopKFlowsDetectionNetFlow")
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
    data = pd.read_csv("Calculations"+fileString+"/TopKFlows/NetFlow/TopFlowChange.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    sTime = pd.to_datetime(data["sTime"])
    eTime = pd.to_datetime(data["eTime"])

    change = data["Change"]
    srcPort = data["srcPort"]
    dstPort = data["dstPort"]
    protocol = data["protocol"]
    real_label = data["real_label"]

    truePositives = 0
    falsePositives = 0

    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    #Loop through all the flow records in the input file
    for i in range(len(sTime)):
        sTime[i] = sTime[i].replace(tzinfo=None)
        eTime[i] = eTime[i].replace(tzinfo=None)
        if eTime[i] > stopTime:
            break
        if sTime[i] < startTime:
            continue
        attack = real_label[i]
        #simulateRealTime(datetime.now(), sTime[i], attackDate)
        alert = {
            "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
            "Gateway": systemId,
            "Deviation_score": change[i],
            "srcPort": int(srcPort[i]),
            "dstPort": int(dstPort[i]),
            "Protocol": int(protocol[i]),
            "Real_label": int(attack),
            "Attack_type": "Flooding"
        }
        '''alert = {
            "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
            "Gateway": systemId,
            "Deviation_score": change,
            "srcIP": int(rec.sip),
            "dstIP": int(rec.dip),
            "srcPort": srcPort[i],
            "dstPort": dstPort[i],
            "Protocol": protocol[i],
            "Real_label": int(attack),
            "Attack_type": "Flooding"
        }'''
        mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
    
        if attack:
            truePositives += 1
        elif not attack:
            falsePositives += 1
    p = Path('Detections' + fileString)
    q = p / 'TopKFlows' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)

    #Open file to write alerts to
    scores = open(str(q) + "/Scores.TopKFlows.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    scores.write("TP,FP")
    scores.write("\n"+ str(truePositives)+ "," + str(falsePositives))
    scores.close()