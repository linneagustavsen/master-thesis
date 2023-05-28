from datetime import datetime,timedelta
import json
import os
from pathlib import Path
from HelperFunctions.GetData import *
from HelperFunctions.IsAttack import isAttack
import paho.mqtt.client as mqtt

from HelperFunctions.Normalization import normalization
from HelperFunctions.SimulateRealTime import simulateRealTime
from HelperFunctionsTelemetry.GetDataTelemetry import getDataTables

'''
    Calculates deviation score of a traffic measurement and alerts in case of an anomaly
    Input:  
            systemId:   string, name of the system to collect and calculate on,
            if_name:    string, interface name,
            field:      string, what field to detect on
            start:      string, indicates the start time of the testing period
            stop:       string, indicates the stop time of the testing period
            threshold:  int, threshold for when to alert
            attackDate: string, date of the attack to detect
'''
def detectionTelemetry(start, stop, systemId, field, threshold, attackDate):
    json_file = open("Telemetry/Threshold/Calculations/MinMaxValues/MinMax.StatisticalModel." + str(field)+".json", "r")
    maxmin = json.load(json_file)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'thresholdDetectionTelemetry'
    MQTT_PASSWORD = 'thresholdDetectionPass'
    MQTT_TOPIC = 'detections/modules/telemetry'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print(systemId, "Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        s=0
        #print(systemId, "Statistical threshold detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("ThresholdDetectionTelemetry")
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
    data = pd.read_csv("Calculations"+fileString+"/Threshold/Telemetry/" + str(field)+".attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    sTime = pd.to_datetime(data["sTime"])
    eTime = pd.to_datetime(data["eTime"])
    deviations = data["Deviation_score"]

    truePositives = 0
    falsePositives = 0
    falseNegatives = 0
    trueNegatives  = 0

    real_label = data["real_label"]

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
        deviation = deviations[i]
        
        if deviation > threshold:
            #simulateRealTime(datetime.now(), eTime[i], attackDate)
            alert = {
                "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                "Gateway": systemId,
                "Deviation_score": normalization(deviation, maxmin["minimum"], maxmin["maximum"]),
                "Real_label": int(attack),
                "Attack_type": "Flooding"
            }
            mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
            
        if deviation > threshold and attack:
            truePositives += 1
        elif deviation > threshold and not attack:
            falsePositives += 1
        elif deviation <= threshold and attack:
            falseNegatives +=1
        elif deviation <= threshold and not attack:
            trueNegatives += 1

    p = Path('Detections' + fileString)
    r = p / 'Threshold' / 'Telemetry'
    if not r.exists():
        r.mkdir(parents=True)

    scores = open(str(r) + "/Scores." + str(field)+".attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    scores.write("TP,FP,FN,TN")
 
    scores.write("\n"+ str(truePositives)+ "," + str(falsePositives)+ "," + str(falseNegatives)+ "," + str(trueNegatives))
    scores.close()