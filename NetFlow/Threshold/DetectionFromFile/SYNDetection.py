from pathlib import Path
import pandas as pd
from silk import *
from datetime import datetime, timedelta
import numpy as np
import paho.mqtt.client as mqtt
import json
from HelperFunctions.IsAttack import isAttackFlow
from HelperFunctions.Normalization import normalization
from HelperFunctions.SimulateRealTime import simulateRealTime

'''
    Calculates the number of SYN syn in a flow and alerts in case of an anomaly
    Input:  silkFile:   string, file with flow records sorted on time
            start:      string, start time of detection 
            stop:       string, stop time of detection 
            systemId:   string, name of the system to calculate on
            windowSize: int, represents a multiplier of frequency, how far back we want to compare the value with
            threshold:  int, values over this threshold will cause an alert
            attackDate: string, date of the attack the calculations are made on
'''
def synDetection(start, stop, systemId, windowSize, threshold, attackDate):
    p = Path('Detections')
    q = p / 'Threshold' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    #Open file to write alerts to
    scores = open(str(q) + "/Scores.SYN.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    scores.write("TP,FP,FN,TN")

    p = Path('NetFlow')
    q = p / 'Threshold' / 'Calculations'
    if not q.exists():
        q = Path('Threshold')
        q = q / 'Calculations'
    json_file_syn = open(str(q) + "/MinMax.syn.json", "r")
    maxmin_syn = json.load(json_file_syn)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'synDetectionNetFlow'
    MQTT_PASSWORD = 'synDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("SYN detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("SYNDetectionNetFlow")
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)

    data = pd.read_csv("Calculations0803/Threshold/NetFlow/SYN.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    sTime = pd.to_datetime(data["sTime"])
    eTime = pd.to_datetime(data["eTime"])

    synPacketsPerFlow = data["synPacketsPerFlow"]
    srcPort = data["srcPort"]
    dstPort = data["dstPort"]
    #protocol = data["protocol"]
    real_label = data["real_label"]

    truePositives = 0
    falsePositives = 0
    falseNegatives = 0
    trueNegatives  =0

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

        if i >= windowSize:
            change = synPacketsPerFlow[i] - np.nanmean(synPacketsPerFlow[i-windowSize: i-1])
            attack = real_label[i]
            #simulateRealTime(datetime.now(), eTime[i], attackDate)
            if synPacketsPerFlow[i] >= threshold:
                alert = {
                        "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "Deviation_score": normalization(abs(change), maxmin_syn["minimum"], maxmin_syn["maximum"]),
                        '''"srcIP": int(rec.sip),
                        "dstIP": int(rec.dip),'''
                        "srcPort": int(srcPort[i]),
                        "dstPort": int(dstPort[i]),
                        #"Protocol": protocol[i],
                        "Real_label": int(attack),
                        "Attack_type": "SYN Flood"
                        }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
            
            if synPacketsPerFlow[i] > threshold and attack:
                truePositives += 1
            elif synPacketsPerFlow[i] > threshold and not attack:
                falsePositives += 1
            elif synPacketsPerFlow[i] <= threshold and attack:
                falseNegatives +=1
            elif synPacketsPerFlow[i] <= threshold and not attack:
                trueNegatives += 1
        else:
            if attack:
                falseNegatives += 1
            elif not attack:
                trueNegatives += 1
    
    scores.write("\n"+ str(truePositives)+ "," + str(falsePositives)+ "," + str(falseNegatives)+ "," + str(trueNegatives))
    scores.close()