from datetime import timedelta,datetime
from pathlib import Path
import pickle
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import numpy as np
import paho.mqtt.client as mqtt
import json

from HelperFunctions.SimulateRealTime import simulateRealTime

'''
    Detect anomalies based on a random forest classifier and write them to file
    Specifically without IPs
    Input:  trainingSet:    pandas dataframe, training data set
            testingSet:     pandas dataframe, testing data set
            systemId:       string, name of the system to collect and detect on  
            attackDate:     string, date of the attack the detections are made on
'''
def detectionRandomForestNoIPNetFlowFields(systemId, attackDate):
    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'randomForestNoIPDetectionNetFlow'
    MQTT_PASSWORD = 'randomForestNoIPDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("Random Forest fields no IP detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("RandomForestNoIPDetectionNetFlow")
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)

    alerts = pd.read_csv("Calculations0803/RandomForest/NetFlow/AlertsNoIP.Fields.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
    sTime = pd.to_datetime(alerts["sTime"])
    eTime = pd.to_datetime(alerts["eTime"])

    srcPort = alerts["srcPort"]
    dstPort = alerts["dstPort"]
    protocol = alerts["protocol"]
    real_label = alerts["real_label"]

    for i in range(len(sTime)):
        #simulateRealTime(datetime.now(), eTime[i], attackDate)
       
        alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "srcPort": srcPort[i],
                    "dstPort": dstPort[i],
                    "Protocol": protocol[i],
                    "Deviation_score": None,
                    "Real_label": real_label[i],
                    "Attack_type": ""
                }
        mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))