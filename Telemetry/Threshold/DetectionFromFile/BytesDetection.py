from datetime import datetime,timedelta
from pathlib import Path
import numpy as np
from HelperFunctions.GetData import *
from HelperFunctions.GeneralizedEntropy import *
from HelperFunctions.Distributions import *
from HelperFunctions.IsAttack import isAttack
import json
import paho.mqtt.client as mqtt

from HelperFunctions.Normalization import normalization
from HelperFunctions.SimulateRealTime import simulateRealTime
from HelperFunctionsTelemetry.GetDataTelemetry import getData

'''
    Calculates entropy, packet and byte count and alerts in case of an anomaly
    Input:  start:                  string, indicating the start time of the data to detect on
            stop:                   string, indicating the stop time of the data to detect on
            systemId:               string, name of the system to collect and calculate on  
            if_name:                string, interface name, 
            interval:               timedelta object, size of the sliding window which the calculation is made on,
            frequency:              timedelta object, frequency of metric calculation,
            windowSize:             int, represents a multiplier of frequency, how far back we want to compare the value with
            thresholdBytes:         float, values over this threshold will cause an alert
            attackDate:             string, date of the attack the calculations are made on
'''

def detectionBytesTelemetry(start, stop, systemId, frequency, interval, windowSize, thresholdBytes, attackDate):
    p = Path('Detections')
    r = p / 'Threshold' / 'Telemetry'
    if not r.exists():
        r.mkdir(parents=True)
    #Open file to write alerts to
    scores = open(str(r) + "/Scores.NumberOfBytes."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    scores.write("TP,FP,FN,TN")

    json_file = open("Telemetry/Threshold/Calculations/MinMax.bytes."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin = json.load(json_file)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'bytesDetectionTelemetry'
    MQTT_PASSWORD = 'bytesDetectionPass'
    MQTT_TOPIC = 'detections/modules/telemetry'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client,userdata,result):
        print("Bytes detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("BytesDetectionTelemetry")
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)

    data = pd.read_csv("Calculations0803/Entropy/Telemetry/Metrics."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    sTime = pd.to_datetime(data["sTime"])
    eTime = pd.to_datetime(data["eTime"])


    bytesArray = data["numberOfBytes"]
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
        if eTime[i] > stopTime + frequency:
            break
        if sTime[i] < startTime:
            continue

        attack = real_label[i]
        #Compare the difference of each metric with a threshold
        if i >= windowSize:
            change = bytesArray[i] - np.nanmean(bytesArray[i-windowSize: i-1])
            
            simulateRealTime(datetime.now(), eTime[i], attackDate)
            if abs(change) > thresholdBytes:
                alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change), maxmin["minimum"], maxmin["maximum"]),
                    "Real_label": int(attack),
                    "Attack_type": "Flooding"
                }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
            
            if abs(change) > thresholdBytes and attack:
                truePositives += 1
            elif abs(change) > thresholdBytes and not attack:
                falsePositives += 1
            elif abs(change) <= thresholdBytes and attack:
                falseNegatives +=1
            elif abs(change) <= thresholdBytes and not attack:
                trueNegatives += 1
        else:
            if attack:
                falseNegatives +=1
            elif not attack:
                trueNegatives += 1
    scores.write("\n"+ str(truePositives)+ "," + str(falsePositives)+ "," + str(falseNegatives)+ "," + str(trueNegatives))
    scores.close()