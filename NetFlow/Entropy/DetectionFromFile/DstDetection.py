from pathlib import Path
import pandas as pd
from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime, timedelta
import numpy as np
import json
import paho.mqtt.client as mqtt
from time import sleep
from random import randrange
from HelperFunctions.IsAttack import isAttack
from HelperFunctions.Normalization import normalization
from HelperFunctions.SimulateRealTime import simulateRealTime

'''
    Calculates destination IP entropy and entropy rate and alerts in case of an anomaly
    Input:  
            silkFile:                       string, file with flow records sorted on time
            start:                          string, indicating the start time of the data wanted
            stop:                           string, indicating the stop time of the data wanted
            systemId:                       string, name of the system to collect and calculate on
            frequency:                      timedelta object, frequency of metric calculation
            interval:                       timedelta object, size of the sliding window which the calculation is made on
            windowSize:                     int, represents a multiplier of frequency, how far back we want to compare the value with
            thresholdDstEntropy:            float, values over this threshold will cause an alert
            thresholdDstEntropyRate:        float, values over this threshold will cause an alert
            attackDate:                     string, date of the attack the calculations are made on
'''
def detectionDst(start, stop, systemId, frequency, interval, windowSize, thresholdDstEntropy, thresholdDstEntropyRate, attackDate):
    p = Path('NetFlow')
    q = p / 'Entropy' / 'Calculations'
    if not q.exists():
        q = Path('Entropy')
        q = q / 'Calculations'
    json_file_dip = open(str(q) + "/MinMaxValues/MinMax.dip."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_dip = json.load(json_file_dip)
    json_file_dip_rate = open(str(q) + "/MinMaxValues/MinMax.dip_rate."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_dip_rate = json.load(json_file_dip_rate)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'dstEntropyDetectionNetFlow'
    MQTT_PASSWORD = 'dstEntropyDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        s=0
        #print(systemId, "Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        s=0
        #print(systemId, "Destination flow entropy detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("DestinationFlowEntropyDetectionNetFlow")
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
    data = pd.read_csv("Calculations"+fileString+"/Entropy/NetFlow/Metrics."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    sTime = pd.to_datetime(data["sTime"])
    eTime = pd.to_datetime(data["eTime"])


    dstEntropy = data["dstEntropy"]
    dstEntropyRate = data["dstEntropyRate"]

    attackFlows = pd.read_csv("Calculations"+fileString+"/Entropy/NetFlow/AttackFlows.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
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
            change = dstEntropy[i] - np.nanmean(dstEntropy[i-windowSize: i-1])
            change_r = dstEntropyRate[i] - np.nanmean(dstEntropyRate[i-windowSize: i-1])
            if change < 0 and change_r < 0:
                attackType = "Low-Rate"
            elif change_r < 0:
                attackType = "Flooding"
            else:
                attackType = ""
            simulateRealTime(datetime.now(), eTime[i], attackDate)
            if abs(change) > thresholdDstEntropy:
                alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change), maxmin_dip["minimum"], maxmin_dip["maximum"]),
                    "Real_label": int(attack),
                    "Attack_type": attackType
                    }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
            if abs(change_r) >  thresholdDstEntropyRate:
                alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change_r), maxmin_dip_rate["minimum"], maxmin_dip_rate["maximum"]),
                    "Real_label": int(attack),
                    "Attack_type": attackType
                    }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
            
            if abs(change) > thresholdDstEntropy and attack:
                truePositives += 1
            elif abs(change) > thresholdDstEntropy and not attack:
                falsePositives += 1
            elif abs(change) <= thresholdDstEntropy and attack:
                falseNegatives +=1
            elif abs(change) <= thresholdDstEntropy and not attack:
                trueNegatives += 1
            
            if abs(change_r) > thresholdDstEntropyRate and attack:
                truePositives_r += 1
            elif abs(change_r) > thresholdDstEntropyRate and not attack:
                falsePositives_r += 1
            elif abs(change_r) <= thresholdDstEntropyRate and attack:
                falseNegatives_r += 1
            elif abs(change_r) <= thresholdDstEntropyRate and not attack:
                trueNegatives_r += 1
        else:
            if attack:
                falseNegatives += 1
                falseNegatives_r += 1
            elif not attack:
                trueNegatives += 1
                trueNegatives_r += 1

    sleep(randrange(400))
    p = Path('Detections' + fileString)
    q = p / 'Entropy' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    #Open files to write alerts to
    scores = open(str(q) + "/Scores.DestinationIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    scores_r = open(str(q) + "/Scores.DestinationIPEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    scores.write("TP,FP,FN,TN")
    scores_r.write("TP,FP,FN,TN")
    scores.write("\n"+ str(truePositives)+ "," + str(falsePositives)+ "," + str(falseNegatives)+ "," + str(trueNegatives))
    scores.close()

    scores_r.write("\n"+ str(truePositives_r)+ "," + str(falsePositives_r)+ "," + str(falseNegatives_r)+ "," + str(trueNegatives_r))
    scores_r.close()