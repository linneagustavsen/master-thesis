from datetime import datetime,timedelta
from pathlib import Path
import numpy as np
from HelperFunctions.GetData import *
from HelperFunctions.GeneralizedEntropy import *
from HelperFunctions.Distributions import *
from HelperFunctions.IsAttack import isAttack
import json
import paho.mqtt.client as mqtt
from time import sleep
from random import randrange
from HelperFunctions.AttackIntervals import inAttackInterval

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
            thresholdPackets:       float, values over this threshold will cause an alert
            attackDate:             string, date of the attack the calculations are made on
'''
def detectionPacketsTelemetry(start, stop, systemId, frequency, interval, windowSize, thresholdPackets_ingress, thresholdPackets_egress,  weight_ingress, weight_egress, attackDate):
    
    json_file_ingress = open("Telemetry/Threshold/Calculations/MinMaxValues/MinMax.packets_ingress."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_ingress = json.load(json_file_ingress)

    json_file_egress = open("Telemetry/Threshold/Calculations/MinMaxValues/MinMax.packets_egress."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_egress = json.load(json_file_egress)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'packetsDetectionTelemetry'
    MQTT_PASSWORD = 'packetsDetectionPass'
    MQTT_TOPIC = 'detections/modules/telemetry'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        s=0
        #print(systemId, "Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print(systemId, "Packet detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("PacketsDetectionTelemetry")
    #mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
    mqtt_client.loop_start()

    if attackDate == "08.03.23":
        fileString = "0803"
        attackDict_ingress = {"SYN Flood":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "SlowLoris": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "Ping Flood": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "R.U.D.Y":{"TP":0, "FP":0, "TN": 0, "FN": 0}}
        attackDict_egress = {"SYN Flood":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "SlowLoris": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "Ping Flood": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "R.U.D.Y":{"TP":0, "FP":0, "TN": 0, "FN": 0}}
    elif attackDate == "17.03.23":
        fileString = "1703"
        attackDict_ingress = {"SYN Flood":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "SlowLoris": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "Ping Flood": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "R.U.D.Y":{"TP":0, "FP":0, "TN": 0, "FN": 0}}
        attackDict_egress = {"SYN Flood":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "SlowLoris": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "Ping Flood": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "R.U.D.Y":{"TP":0, "FP":0, "TN": 0, "FN": 0}}
    elif attackDate == "24.03.23":
        fileString = "2403"
        attackDict_ingress = {"UDP Flood":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "SlowLoris": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "Ping Flood": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "Slow Read":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "Blacknurse":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "SYN Flood":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "R.U.D.Y":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "Xmas":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "UDP Flood and SlowLoris":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "Ping Flood and R.U.D.Y":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "All types":{"TP":0, "FP":0, "TN": 0, "FN": 0}}
        attackDict_egress = {"UDP Flood":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "SlowLoris": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "Ping Flood": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "Slow Read":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "Blacknurse":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "SYN Flood":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "R.U.D.Y":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "Xmas":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "UDP Flood and SlowLoris":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "Ping Flood and R.U.D.Y":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "All types":{"TP":0, "FP":0, "TN": 0, "FN": 0}}
    data = pd.read_csv("Calculations"+fileString+"/Entropy/Telemetry/Metrics."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    sTime = pd.to_datetime(data["sTime"])
    eTime = pd.to_datetime(data["eTime"])


    packetNumberArray_ingress = data["numberOfPackets_ingress"]
    packetNumberArray_egress = data["numberOfPackets_egress"]
    real_label = data["real_label"]
 
    truePositives_ingress = 0
    falsePositives_ingress = 0
    falseNegatives_ingress = 0
    trueNegatives_ingress  = 0

    truePositives_egress = 0
    falsePositives_egress = 0
    falseNegatives_egress = 0
    trueNegatives_egress  = 0

    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    #Loop through all the flow records in the input file
    for i in range(len(sTime)):
        isInAttackTime, attackTypeDuringThisTime = inAttackInterval(sTime[i], eTime[i], attackDate)
        sTime[i] = sTime[i].replace(tzinfo=None)
        eTime[i] = eTime[i].replace(tzinfo=None)
        if eTime[i] > stopTime + frequency:
            break
        if sTime[i] < startTime:
            continue

        attack = real_label[i]
        #Compare the difference of each metric with a threshold
        if i >= windowSize:
            change_ingress = packetNumberArray_ingress[i] - np.nanmean(packetNumberArray_ingress[i-windowSize: i-1])
            change_egress = packetNumberArray_egress[i] - np.nanmean(packetNumberArray_egress[i-windowSize: i-1])
            
            simulateRealTime(datetime.now(), eTime[i], attackDate)
            if abs(change_ingress) > thresholdPackets_ingress:
                alert = {
                   "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change_ingress), maxmin_ingress["minimum"], maxmin_ingress["maximum"]),
                    "Real_label": int(attack),
                    "Attack_type": "Flooding",
                    "Weight": weight_ingress
                }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

            if abs(change_egress) > thresholdPackets_egress:
                alert = {
                   "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change_egress), maxmin_egress["minimum"], maxmin_egress["maximum"]),
                    "Real_label": int(attack),
                    "Attack_type": "Flooding",
                    "Weight": weight_egress
                }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

            if abs(change_ingress) > thresholdPackets_ingress and attack:
                truePositives_ingress += 1
                if isInAttackTime:
                    attackDict_ingress[attackTypeDuringThisTime]["TP"] += 1
            elif abs(change_ingress) > thresholdPackets_ingress and not attack:
                falsePositives_ingress += 1
                if isInAttackTime:
                    attackDict_ingress[attackTypeDuringThisTime]["FP"] += 1
            elif abs(change_ingress) <= thresholdPackets_ingress and attack:
                falseNegatives_ingress +=1
                if isInAttackTime:
                    attackDict_ingress[attackTypeDuringThisTime]["FN"] += 1
            elif abs(change_ingress) <= thresholdPackets_ingress and not attack:
                trueNegatives_ingress += 1
                if isInAttackTime:
                    attackDict_ingress[attackTypeDuringThisTime]["TN"] += 1

            if abs(change_egress) > thresholdPackets_egress and attack:
                truePositives_egress += 1
                if isInAttackTime:
                    attackDict_egress[attackTypeDuringThisTime]["TP"] += 1
            elif abs(change_egress) > thresholdPackets_egress and not attack:
                falsePositives_egress += 1
                if isInAttackTime:
                    attackDict_egress[attackTypeDuringThisTime]["FP"] += 1
            elif abs(change_egress) <= thresholdPackets_egress and attack:
                falseNegatives_egress +=1
                if isInAttackTime:
                    attackDict_egress[attackTypeDuringThisTime]["FN"] += 1
            elif abs(change_egress) <= thresholdPackets_egress and not attack:
                trueNegatives_egress += 1
                if isInAttackTime:
                    attackDict_egress[attackTypeDuringThisTime]["TN"] += 1
        else:
            if attack:
                falseNegatives_ingress +=1
                falseNegatives_egress +=1
                if isInAttackTime:
                    attackDict_ingress[attackTypeDuringThisTime]["FN"] += 1
                    attackDict_egress[attackTypeDuringThisTime]["FN"] += 1
            elif not attack:
                trueNegatives_ingress += 1
                trueNegatives_egress += 1
                if isInAttackTime:
                    attackDict_ingress[attackTypeDuringThisTime]["TN"] += 1
                    attackDict_egress[attackTypeDuringThisTime]["TN"] += 1
    #sleep(randrange(400))
    p = Path('Detections' + fileString)
    r = p / 'Threshold' / 'Telemetry'
    if not r.exists():
        r.mkdir(parents=True)
    #Open file to write alerts to
    scores_ingress = open(str(r) + "/Scores.NumberOfPackets_ingress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    scores_ingress.write("TP,FP,FN,TN")
    scores_ingress.write("\n"+ str(truePositives_ingress)+ "," + str(falsePositives_ingress)+ "," + str(falseNegatives_ingress)+ "," + str(trueNegatives_ingress))
    scores_ingress.close()

    scores_egress = open(str(r) + "/Scores.NumberOfPackets_egress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    scores_egress.write("TP,FP,FN,TN")
    scores_egress.write("\n"+ str(truePositives_egress)+ "," + str(falsePositives_egress)+ "," + str(falseNegatives_egress)+ "," + str(trueNegatives_egress))
    scores_egress.close()

    attackScores = open(str(r) + "/ScoresAttacks.NumberOfPackets_ingress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json", "w")
    json.dump(attackDict_ingress,attackScores)
    attackScores.close()

    attackScores = open(str(r) + "/ScoresAttacks.NumberOfPackets_egress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json", "w")
    json.dump(attackDict_egress,attackScores)
    attackScores.close()