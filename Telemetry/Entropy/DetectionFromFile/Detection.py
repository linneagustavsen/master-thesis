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

from HelperFunctions.Normalization import normalization

'''
    Calculates entropy, packet and byte count and alerts in case of an anomaly
    Input:  start:                  string, indicating the start time of the data to detect on
            stop:                   string, indicating the stop time of the data to detect on
            systemId:               string, name of the system to collect and calculate on  
            if_name:                string, interface name, 
            interval:               timedelta object, size of the sliding window which the calculation is made on,
            frequency:              timedelta object, frequency of metric calculation,
            windowSize:             int, represents a multiplier of frequency, how far back we want to compare the value with
            thresholdEntropy:       float, values over this threshold will cause an alert
            thresholdEntropyRate:   float, values over this threshold will cause an alert
            attackDate:             string, date of the attack the calculations are made on
'''
def detectionEntropyTelemetry(start, stop, systemId, frequency, interval, windowSize, thresholdEntropy, thresholdEntropyRate, attackDate):

    json_file = open("Telemetry/Entropy/Calculations/MinMaxValues/MinMax.packet_size."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin = json.load(json_file)
    json_file_rate = open("Telemetry/Entropy/Calculations/MinMaxValues/MinMax.packet_size_rate."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_rate = json.load(json_file_rate)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'entropyDetectionTelemetry'
    MQTT_PASSWORD = 'entropyDetectionPass'
    MQTT_TOPIC = 'detections/modules/telemetry'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        s=0
        #print(systemId, "Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        s=0
        #print(systemId, "Entropy detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("EntropyDetectionTelemetry")
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
    data = pd.read_csv("Calculations"+fileString+"/Entropy/Telemetry/Metrics."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    sTime = pd.to_datetime(data["sTime"])
    eTime = pd.to_datetime(data["eTime"])
    real_label = data["real_label"]

    packetSizeArray = data["entropy_packet_size"]
    packetSizeRateArray = data["entropy_rate_packet_size"]
    if os.path.exists("Calculations"+fileString+"/Entropy/Telemetry/packetSizeDistributions."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl"):
        packetSizeDistributionDict = pd.read_pickle("Calculations"+fileString+"/Entropy/Telemetry/packetSizeDistributions."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")

    truePositives = 0
    falsePositives = 0
    falseNegatives = 0
    trueNegatives  = 0

    truePositives_r = 0
    falsePositives_r = 0
    falseNegatives_r = 0
    trueNegatives_r  = 0

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
        #If there is not enough stored values to compare with we skip the detection
        if i >= windowSize:
            
            change = packetSizeArray[i] - np.nanmean(packetSizeArray[i-windowSize: i-1])
            change_r = packetSizeRateArray[i] - np.nanmean(packetSizeRateArray[i-windowSize: i-1])

            if change < 0:
                attackType = "Same protocol"
            else:
                attackType = "Different protocols"

            simulateRealTime(datetime.now(), eTime[i], attackDate)
            
            if abs(change) > thresholdEntropy:
                alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change), maxmin["minimum"], maxmin["maximum"]),
                    "Packet_size_distribution": packetSizeDistributionDict[eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")],
                    "Real_label": int(attack),
                    "Attack_type": attackType
                }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

            if abs(change_r) > thresholdEntropyRate:
                alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change_r), maxmin_rate["minimum"], maxmin_rate["maximum"]),
                    "Packet_size_distribution": packetSizeDistributionDict[eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")],
                    "Real_label": int(attack),
                    "Attack_type": attackType
                }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

            if abs(change) > thresholdEntropy and attack:
                truePositives += 1
            elif abs(change) > thresholdEntropy and not attack:
                falsePositives += 1
            elif abs(change) <= thresholdEntropy and attack:
                falseNegatives +=1
            elif abs(change) <= thresholdEntropy and not attack:
                trueNegatives += 1

            
            if abs(change) > thresholdEntropyRate and attack:
                truePositives_r += 1
            elif abs(change) > thresholdEntropyRate and not attack:
                falsePositives_r += 1
            elif abs(change) <= thresholdEntropyRate and attack:
                falseNegatives_r += 1
            elif abs(change) <= thresholdEntropyRate and not attack:
                trueNegatives_r += 1
        else:
            if attack:
               falseNegatives +=1
               falseNegatives_r += 1
            elif not attack:
                trueNegatives += 1
                trueNegatives_r += 1

    #sleep(randrange(400))
    p = Path('Detections' + fileString)
    q = p / 'Entropy' / 'Telemetry'
    if not q.exists():
        q.mkdir(parents=True)

    #Open file to write alerts to
    scores = open(str(q) + "/Scores.EntropyPacketSize."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    scores_r = open(str(q) + "/Scores.EntropyRatePacketSize."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    scores.write("TP,FP,FN,TN")
    scores_r.write("TP,FP,FN,TN")
    scores.write("\n"+ str(truePositives)+ "," + str(falsePositives)+ "," + str(falseNegatives)+ "," + str(trueNegatives))
    scores.close()

    scores_r.write("\n"+ str(truePositives_r)+ "," + str(falsePositives_r)+ "," + str(falseNegatives_r)+ "," + str(trueNegatives_r))
    scores_r.close()
