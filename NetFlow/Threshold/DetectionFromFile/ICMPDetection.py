from pathlib import Path
import pandas as pd
from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime,timedelta
import numpy as np
import paho.mqtt.client as mqtt
import json
from HelperFunctions.IsAttack import isAttack
from HelperFunctions.Normalization import normalization
from HelperFunctions.SimulateRealTime import simulateRealTime

'''
    Calculates entropy and other metrics and alerts in case of an anomaly
    Input:  silkFile:                       string, file with flow records sorted on time
            start:                          string, indicating the start time of the data wanted
            stop:                           string, indicating the stop time of the data wanted
            systemId:                       string, name of the system to collect and calculate on
            frequency:                      timedelta object, frequency of metric calculation
            interval:                       timedelta object, size of the sliding window which the calculation is made on
            windowSize:                     int, represents a multiplier of frequency, how far back we want to compare the value with
            thresholdICMPRatio:             float, values over this threshold will cause an alert
            thresholdNumberOfICMPPackets:   int, values over this threshold will cause an alert
            attackDate:                     string, date of the attack the calculations are made on
'''
def detectionICMP(start, stop, systemId, frequency, interval, windowSize, thresholdICMPRatio, thresholdNumberOfICMPPackets, attackDate):
    p = Path('Detections')
    q = p / 'Threshold' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    #Open file to write alerts to
    scores_r = open(str(q) + "/Scores.ICMPRatio."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    scores = open(str(q) + "/Scores.ICMPPackets."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    
    #Write the column titles to the files
    scores_r.write("TP,FP,FN,TN")
    scores.write("TP,FP,FN,TN")

    p = Path('NetFlow')
    q = p / 'Threshold' / 'Calculations'
    if not q.exists():
        q = Path('Threshold')
        q = q / 'Calculations'
    json_file_packets = open(str(q) + "/MinMax.icmp_packets."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_packets = json.load(json_file_packets)
    json_file_ratio = open(str(q) + "/MinMax.icmp_ratio."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_ratio = json.load(json_file_ratio)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'icmpDetectionNetFlow'
    MQTT_PASSWORD = 'icmpDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("ICMP detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("ICMPDetectionNetFlow")
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)

    data = pd.read_csv("Calculations0803/Entropy/NetFlow/Metrics."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    sTime = pd.to_datetime(data["sTime"])
    eTime = pd.to_datetime(data["eTime"])


    icmpRatioArray = data["icmpRatio"]
    icmpPacketsArray = data["icmpPackets"]

    attackFlows = pd.read_csv("Calculations0803/Entropy/NetFlow/AttackFlows."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
    sTimeAttacks = pd.to_datetime(attackFlows["sTime"])
    eTimeAttacks = pd.to_datetime(attackFlows["eTime"])
   
    attackIntervals = []
    
    lastInterval = pd.Interval(pd.Timestamp.now().replace(tzinfo=None), pd.Timestamp.now().replace(tzinfo=None), closed="both")
    for i in range(len(sTimeAttacks)):
        if sTimeAttacks[i].replace(second=0).replace(tzinfo=None) in lastInterval and eTimeAttacks[i].replace(second=0).replace(tzinfo=None) in lastInterval:
            continue
        elif sTimeAttacks[i].replace(second=0).replace(tzinfo=None) in lastInterval:
            attackIntervals.remove(lastInterval)
            lastInterval = pd.Interval(lastInterval.left, eTimeAttacks[i].replace(second=0).replace(tzinfo=None), closed="both")
            attackIntervals.append(lastInterval)
        
        elif eTimeAttacks[i].replace(second=0).replace(tzinfo=None) in lastInterval:
            attackIntervals.remove(lastInterval)
            lastInterval = pd.Interval(sTimeAttacks[i].replace(second=0).replace(tzinfo=None), lastInterval.right, closed="both")
            attackIntervals.append(lastInterval)
        else:
            lastInterval = pd.Interval(sTimeAttacks[i].replace(second=0).replace(tzinfo=None), eTimeAttacks[i].replace(second=0).replace(tzinfo=None), closed="both")
            attackIntervals.append(lastInterval)

    truePositives = 0
    falsePositives = 0
    falseNegatives = 0
    trueNegatives  =0

    truePositives_r = 0
    falsePositives_r = 0
    falseNegatives_r = 0
    trueNegatives_r  =0

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

        attack = False
        for timeInterval in attackIntervals:
            if sTime[i] in timeInterval or eTime[i] in timeInterval:
                attack = True
        if i >=windowSize:
            change_ratio = icmpRatioArray[i] - np.nanmean(icmpRatioArray[i-windowSize: i-1])
            change_packets = icmpPacketsArray[i] - np.nanmean(icmpPacketsArray[i-windowSize: i-1])
            
            simulateRealTime(datetime.now(), eTime[i], attackDate)
            if abs(change_ratio) > thresholdICMPRatio:
                alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change_ratio), maxmin_ratio["minimum"], maxmin_ratio["maximum"]),
                    "Protocol": "ICMP",
                    "Real_label": int(attack),
                    "Attack_type": "ICMP Flood"
                    }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

            if abs(change_packets) > thresholdNumberOfICMPPackets:
                alert = {
                   "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change_packets), maxmin_packets["minimum"], maxmin_packets["maximum"]),
                    "Protocol": "ICMP",
                    "Real_label": int(attack),
                    "Attack_type": "ICMP Flood"
                    }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

            if abs(change_ratio) > thresholdICMPRatio and attack:
                truePositives_r += 1
            elif abs(change_ratio) > thresholdICMPRatio and not attack:
                falsePositives_r += 1
            elif abs(change_ratio) <= thresholdICMPRatio and attack:
                falseNegatives_r += 1
            elif abs(change_ratio) <= thresholdICMPRatio and not attack:
                trueNegatives_r += 1
            
            if abs(change_packets) > thresholdNumberOfICMPPackets and attack:
                truePositives += 1
            elif abs(change_packets) > thresholdNumberOfICMPPackets and not attack:
                falsePositives += 1
            elif abs(change_packets) <= thresholdNumberOfICMPPackets and attack:
                falseNegatives +=1
            elif abs(change_packets) <= thresholdNumberOfICMPPackets and not attack:
                trueNegatives += 1
        else:
            if attack:
                falseNegatives += 1
                falseNegatives_r += 1
            elif not attack:
               trueNegatives += 1
               trueNegatives_r += 1
    
    scores.write("\n"+ str(truePositives)+ "," + str(falsePositives)+ "," + str(falseNegatives)+ "," + str(trueNegatives))
    scores.close()

    scores_r.write("\n"+ str(truePositives_r)+ "," + str(falsePositives_r)+ "," + str(falseNegatives_r)+ "," + str(trueNegatives_r))
    scores_r.close()