from pathlib import Path
import pandas as pd
from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime, timedelta
import numpy as np
import paho.mqtt.client as mqtt
import json
from HelperFunctions.IsAttack import isAttack
from HelperFunctions.Normalization import normalization
from HelperFunctions.SimulateRealTime import simulateRealTime


'''
    Calculates entropy and alerts in case of an anomaly
    Input:  silkFile:       string, file with flow records sorted on time
            start:          string, indicating the start time of the data wanted
            stop:           string, indicating the stop time of the data wanted
            systemId:       string, name of the system to collect and calculate on
            frequency:      timedelta object, frequency of metric calculation
            interval:       timedelta object, size of the sliding window which the calculation is made on
            windowSize:     int, represents a multiplier of frequency, how far back we want to compare the value with
            thresholdSrc:   float, values over this threshold will cause an alert
            thresholdDst:   float, values over this threshold will cause an alert
            thresholdFlow:  float, values over this threshold will cause an alert
            attackDate:     string, date of the attack the calculations are made on
'''
def synEntropyDetection(start, stop, systemId, frequency, interval, windowSize, thresholdSrc, thresholdDst, thresholdFlow, attackDate):
    p = Path('Detections')
    q = p / 'Entropy' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    #Open files to write alerts to
    scores_s = open(str(q) + "/Scores.SYNSourceIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    scores_d = open(str(q) + "/Scores.SYNDestinationIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    scores_f = open(str(q) + "/Scores.SYNFlowIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    
    #Write the column titles to the files
    scores_s.write("TP,FP,FN,TN")
    scores_d.write("TP,FP,FN,TN")
    scores_f.write("TP,FP,FN,TN")

    p = Path('NetFlow')
    q = p / 'Entropy' / 'Calculations'
    if not q.exists():
        q = Path('Entropy')
        q = q / 'Calculations'
    json_file_src = open(str(q) + "/MinMax.SYN_src."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_src = json.load(json_file_src)
    json_file_dst = open(str(q) + "/MinMax.SYN_dst."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_dst = json.load(json_file_dst)
    json_file_flow = open(str(q) + "/MinMax.SYN_flow."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_flow = json.load(json_file_flow)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'synEntropyDetectionNetFlow'
    MQTT_PASSWORD = 'synEntropyDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("SYN entropy detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("SYNEntropyDetectionNetFlow")
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)

    data = pd.read_csv("Calculations0803/Entropy/NetFlow/SYN."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    sTime = pd.to_datetime(data["sTime"])
    eTime = pd.to_datetime(data["eTime"])

    entropyOfSynPacketsPerSrc = data["srcEntropy"]
    entropyOfSynPacketsPerDst = data["dstEntropy"]
    entropyOfSynPacketsPerFlow = data["flowEntropy"]
    
    attackFlows = pd.read_csv("Calculations0803/Entropy/NetFlow/AttackFlows.SYN."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
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

    truePositives_s = 0
    falsePositives_s = 0
    falseNegatives_s = 0
    trueNegatives_s  = 0

    truePositives_d = 0
    falsePositives_d = 0
    falseNegatives_d = 0
    trueNegatives_d = 0

    truePositives_f = 0
    falsePositives_f = 0
    falseNegatives_f = 0
    trueNegatives_f = 0

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

        #If there is enough stored values to compare with we compare the difference of each metric with a threshold
        if i >=windowSize:
            change_src = entropyOfSynPacketsPerSrc[i] - np.nanmean(entropyOfSynPacketsPerSrc[i-windowSize: i-1])
            change_dst = entropyOfSynPacketsPerDst[i] - np.nanmean(entropyOfSynPacketsPerDst[i-windowSize: i-1])
            change_flow = entropyOfSynPacketsPerFlow[i] - np.nanmean(entropyOfSynPacketsPerFlow[i-windowSize: i-1])

            #simulateRealTime(datetime.now(), eTime[i], attackDate)
            if abs(change_src) > thresholdSrc:
                alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change_src), maxmin_src["minimum"], maxmin_src["maximum"]),
                    "Protocol": "TCP",
                    "Real_label": int(attack),
                    "Attack_type": "SYN Flood"
                    }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
            if abs(change_dst) > thresholdDst:
                alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change_dst), maxmin_dst["minimum"], maxmin_dst["maximum"]),
                    "Protocol": "TCP",
                    "Real_label": int(attack),
                    "Attack_type": "SYN Flood"
                    }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
            if abs(change_flow) > thresholdFlow:
                alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change_flow), maxmin_flow["minimum"], maxmin_flow["maximum"]),
                    "Protocol": "TCP",
                    "Real_label": int(attack),
                    "Attack_type": "SYN Flood"
                    }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
        
            if abs(change_src) > thresholdSrc and attack:
                truePositives_s += 1
            elif abs(change_src) > thresholdSrc and not attack:
                falsePositives_s += 1
            elif abs(change_src) <= thresholdSrc and attack:
                falseNegatives_s += 1
            elif abs(change_src) <= thresholdSrc and not attack:
                trueNegatives_s += 1
            
            if abs(change_dst) > thresholdDst and attack:
                truePositives_d += 1
            elif abs(change_dst) > thresholdDst and not attack:
                falsePositives_d += 1
            elif abs(change_dst) <= thresholdDst and attack:
                falseNegatives_d += 1
            elif abs(change_dst) <= thresholdDst and not attack:
                trueNegatives_d += 1
            
            if abs(change_flow) > thresholdFlow and attack:
                truePositives_f += 1
            elif abs(change_flow) > thresholdFlow and not attack:
                falsePositives_f += 1
            elif abs(change_flow) <= thresholdFlow and attack:
                falseNegatives_f += 1
            elif abs(change_flow) <= thresholdFlow and not attack:
                trueNegatives_f += 1
        else:
            if attack:
                falseNegatives_s += 1
                falseNegatives_d += 1
                falseNegatives_f += 1
            elif not attack:
                trueNegatives_s += 1
                trueNegatives_d += 1
                trueNegatives_f += 1

    scores_s.write("\n"+ str(truePositives_s)+ "," + str(falsePositives_s)+ "," + str(falseNegatives_s)+ "," + str(trueNegatives_s))
    scores_s.close()

    scores_d.write("\n"+ str(truePositives_d)+ "," + str(falsePositives_d)+ "," + str(falseNegatives_d)+ "," + str(trueNegatives_d))
    scores_d.close()

    scores_f.write("\n"+ str(truePositives_f)+ "," + str(falsePositives_f)+ "," + str(falseNegatives_f)+ "," + str(trueNegatives_f))
    scores_f.close()