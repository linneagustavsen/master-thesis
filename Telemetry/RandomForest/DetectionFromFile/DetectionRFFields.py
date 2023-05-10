from datetime import datetime, timedelta
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import numpy as np
import json
import paho.mqtt.client as mqtt
import pickle

from HelperFunctions.SimulateRealTime import simulateRealTime

'''
    Detect anomalies based on a random forest classifier
    Input:  
            trainingSet:    pandas dataframe, training data set
            testingSet:     pandas dataframe, testing data set
            systemId:       string, name of the system to collect and calculate on  
            interval:       timedelta object, size of the sliding window which the calculation is made on
            attackDate:     string, date of the attack the calculations are made on
'''
def detectionRandomForestTelemetry(systemId, attackDate):
    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'randomForestDetectionTelemetry'
    MQTT_PASSWORD = 'randomForestDetectionPass'
    MQTT_TOPIC = 'detections/modules/telemetry'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client,userdata,result):
        print("Random Forest detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("RandomForestDetectionTelemetry")
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)

    alerts = pd.read_csv("Calculations0803/RandomForest/Telemetry/Alerts.Fields.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
    sTime = pd.to_datetime(alerts["sTime"])
    eTime = pd.to_datetime(alerts["eTime"])

    real_label = alerts["real_label"]

    for i in range(len(sTime)):
        #simulateRealTime(datetime.now(), eTime[i], attackDate)
       
        alert = {
                "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": None,
                    #"Value": testingMeasurements[i],
                    "Real_label": real_label[i],
                    "Attack_type": "Flooding"
                }
        mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))