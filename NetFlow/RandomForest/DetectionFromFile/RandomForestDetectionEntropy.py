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
    Input:  trainingSet:    pandas dataframe, training data set
            testingSet:     pandas dataframe, testing data set
            systemId:       string, name of the system to collect and detct on  
            interval:       timedelta object, size of the sliding window which the detection is made on
            attackDate:     string, date of the attack the detection are made on
'''
def detectionRandomForestNetFlowEntropy(start, stop, systemId, interval, attackDate):
    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'randomForestEntropyDetectionNetFlow'
    MQTT_PASSWORD = 'randomForestEntropyDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print(systemId, "Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        s=0
        #print(systemId, "Random forest entropy detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("RandomForestEntropyDetectionNetFlow")
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
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')

    alerts = pd.read_csv("Calculations"+fileString+"/RandomForest/NetFlow/Alerts.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
    sTime = pd.to_datetime(alerts["sTime"])
    eTime = pd.to_datetime(alerts["eTime"])

    real_label = alerts["real_label"]

    for i in range(len(sTime)):
        sTime[i] = sTime[i].replace(tzinfo=None)
        eTime[i] = eTime[i].replace(tzinfo=None)
        if eTime[i] > stopTime:
            break
        if sTime[i] < startTime:
            continue
        #simulateRealTime(datetime.now(), eTime[i], attackDate)
        alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": None,
                    "Real_label": int(real_label[i]),
                    "Attack_type": ""
                }
        mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))