import os
from pathlib import Path
import pandas as pd
from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime,timedelta
import numpy as np
import json
import paho.mqtt.client as mqtt
from HelperFunctions.IsAttack import isAttack
from HelperFunctions.Normalization import normalization
from HelperFunctions.SimulateRealTime import simulateRealTime

'''
    Calculates packet size entropy and entropy rate and alerts in case of an anomaly
    Input:  
            silkFile:                       string, file with flow records sorted on time
            start:                          string, indicating the start time of the data wanted
            stop:                           string, indicating the stop time of the data wanted
            systemId:                       string, name of the system to collect and calculate on
            frequency:                      timedelta object, frequency of metric calculation
            interval:                       timedelta object, size of the sliding window which the calculation is made on
            windowSize:                     int, represents a multiplier of frequency, how far back we want to compare the value with
            thresholdPSEntropy:             float, values over this threshold will cause an alert
            thresholdPSEntropyRate:         float, values over this threshold will cause an alert
            attackDate:                     string, date of the attack the calculations are made on
'''
def detectionPS(start, stop, systemId, frequency, interval, windowSize, thresholdPSEntropy, thresholdPSEntropyRate, attackDate):
    p = Path('NetFlow')
    q = p / 'Entropy' / 'Calculations'
    if not q.exists():
        q = Path('Entropy')
        q = q / 'Calculations'
    json_file_ps = open(str(q) + "/MinMaxValues/MinMax.packet_size."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_ps = json.load(json_file_ps)
    json_file_ps_rate = open(str(q) + "/MinMaxValues/MinMax.packet_size_r."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_ps_rate = json.load(json_file_ps_rate)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'packetSizeEntropyDetectionNetFlow'
    MQTT_PASSWORD = 'packetSizeEntropyDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print(systemId, "Packet size entropy detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("PacketSizeEntropyDetectionNetFlow")
    #mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
    mqtt_client.loop_start()

    data = pd.read_csv("Calculations0803/Entropy/NetFlow/Metrics."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    sTime = pd.to_datetime(data["sTime"])
    eTime = pd.to_datetime(data["eTime"])


    packetSizeEntropy = data["packetSizeEntropy"]
    packetSizeEntropyRate = data["packetSizeEntropyRate"]
    if os.path.exists("Calculations0803/Entropy/NetFlow/packetSizeDistributions."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl"):
        packetSizeDistributionDict = pd.read_pickle("Calculations0803/Entropy/NetFlow/packetSizeDistributions."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    if os.path.exists("Calculations0803/Entropy/NetFlow/packetSizeDistributions."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json"):
        jsonFilePS = open("Calculations0803/Entropy/NetFlow/packetSizeDistributions.300secInterval.attack.08.03.bergen-gw3.json", "r")
        packetSizeDistributionDict = json.load(jsonFilePS)
    
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

        attack = False
        for timeInterval in attackIntervals:
            if sTime[i] in timeInterval or eTime[i] in timeInterval:
                attack = True
        #If there is enough stored values to compare with we compare the difference of each metric with a threshold
        if i >=windowSize:
            change = packetSizeEntropy[i] - np.nanmean(packetSizeEntropy[i-windowSize: i-1])
            change_r = packetSizeEntropyRate[i] - np.nanmean(packetSizeEntropyRate[i-windowSize: i-1])
            
            thisPacketSizeDistributionDict = {}
            thisInterval = pd.Interval(sTime[i], eTime[i], closed="both")
            for time in packetSizeDistributionDict:
                if pd.Timestamp(time).replace(tzinfo=None) in thisInterval:
                    thisPacketSizeDistributionDict = packetSizeDistributionDict[time]
            
            if change < 0:
                    attackType = "Same protocol"
            else:
                attackType = "Different protocols"

            simulateRealTime(datetime.now(), eTime[i], attackDate)
            if abs(change) > thresholdPSEntropy:
                alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change), maxmin_ps["minimum"], maxmin_ps["maximum"]),
                    "Packet_size_distribution": thisPacketSizeDistributionDict,
                    "Real_label": int(attack),
                    "Attack_type": attackType
                }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
                
            if abs(change_r) > thresholdPSEntropyRate:
                alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change_r), maxmin_ps_rate["minimum"], maxmin_ps_rate["maximum"]),
                    "Packet_size_distribution": thisPacketSizeDistributionDict,
                    "Real_label": int(attack),
                    "Attack_type": attackType
                }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
            
            if abs(change) > thresholdPSEntropy and attack:
                truePositives += 1
            elif abs(change) > thresholdPSEntropy and not attack:
                falsePositives += 1
            elif abs(change) <= thresholdPSEntropy and attack:
                falseNegatives +=1
            elif abs(change) <= thresholdPSEntropy and not attack:
                trueNegatives += 1
            
            if abs(change_r) > thresholdPSEntropyRate and attack:
                truePositives_r += 1
            elif abs(change_r) > thresholdPSEntropyRate and not attack:
                falsePositives_r += 1
            elif abs(change_r) <= thresholdPSEntropyRate and attack:
                falseNegatives_r += 1
            elif abs(change_r) <= thresholdPSEntropyRate and not attack:
                trueNegatives_r += 1
        else:
            if attack:
                falseNegatives +=1
                falseNegatives_r += 1
            elif not attack:
                trueNegatives += 1
                trueNegatives_r += 1

    p = Path('Detections')
    q = p / 'Entropy' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    
    #Open files to write alerts to
    scores = open(str(q) + "/Scores.PacketSizeEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    scores_r = open(str(q) + "/Scores.PacketSizeEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    scores.write("TP,FP,FN,TN")
    scores_r.write("TP,FP,FN,TN")

    scores.write("\n"+ str(truePositives)+ "," + str(falsePositives)+ "," + str(falseNegatives)+ "," + str(trueNegatives))
    scores.close()

    scores_r.write("\n"+ str(truePositives_r)+ "," + str(falsePositives_r)+ "," + str(falseNegatives_r)+ "," + str(trueNegatives_r))
    scores_r.close()