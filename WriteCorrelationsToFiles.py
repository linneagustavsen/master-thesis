from datetime import datetime,timedelta
import os
from pathlib import Path
import numpy as np
from HelperFunctions.IsAttack import isAttack
from HelperFunctions.SimulateRealTime import simulateRealTime
from HelperFunctionsTelemetry.GetDataTelemetry import *
from HelperFunctions.GeneralizedEntropy import *
from HelperFunctions.Distributions import *
import json
import paho.mqtt.client as mqtt
from time import sleep
from random import randrange


def writeDetectionsToFile():

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_TOPIC_aggregation = 'detections/modules/telemetry'
    MQTT_TOPIC_attackType = 'detections/aggregation/attackType'
    MQTT_TOPIC_distribution = 'detections/aggregation/distribution'
    MQTT_TOPIC_ips = 'detections/aggregation/ips'
    MQTT_TOPIC_time = 'detections/aggregation/time'
    MQTT_TOPIC_ranking = 'detections/correlation'
    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        s=0
        #print(systemId, "Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        s=0
        #print(systemId, "Entropy detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("Write to file")
    #mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
    mqtt_client.loop_start()

    
    alert = {
        "sTime": "WRITE"
    }
    mqtt_client.publish(MQTT_TOPIC_aggregation,json.dumps(alert))
    mqtt_client.publish(MQTT_TOPIC_attackType,json.dumps(alert))
    mqtt_client.publish(MQTT_TOPIC_distribution,json.dumps(alert))
    mqtt_client.publish(MQTT_TOPIC_ips,json.dumps(alert))
    mqtt_client.publish(MQTT_TOPIC_time,json.dumps(alert))
    mqtt_client.publish(MQTT_TOPIC_ranking,json.dumps(alert))
