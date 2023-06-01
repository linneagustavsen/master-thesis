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
    Calculates bi-directional flow entropy and entropy rate and alerts in case of an anomaly
    Input:  
            silkFile:                       string, file with flow records sorted on time
            start:                          string, indicating the start time of the data wanted
            stop:                           string, indicating the stop time of the data wanted
            systemId:                       string, name of the system to collect and calculate on
            frequency:                      timedelta object, frequency of metric calculation
            interval:                       timedelta object, size of the sliding window which the calculation is made on
            windowSize:                     int, represents a multiplier of frequency, how far back we want to compare the value with
            thresholdFlowEntropy:           float, values over this threshold will cause an alert
            thresholdFlowEntropyRate:       float, values over this threshold will cause an alert
            thresholdNumberOfFlows:         int, values over this threshold will cause an alert
            attackDate:                     string, date of the attack the calculations are made on
'''
def detectionFlow(start, stop, systemId, frequency, interval, windowSize, thresholdFlowEntropy, thresholdFlowEntropyRate, thresholdNumberOfFlows, attackDate):
    p = Path('NetFlow')
    q = p / 'Entropy' / 'Calculations'
    if not q.exists():
        q = Path('Entropy')
        q = q / 'Calculations'
    json_file_flow = open(str(q) + "/MinMaxValues/MinMax.flow."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_flow = json.load(json_file_flow)
    json_file_flow_rate = open(str(q) + "/MinMaxValues/MinMax.f_rate."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_flow_rate = json.load(json_file_flow_rate)
    json_file_nf = open(str(q) + "/MinMaxValues/MinMax.nf."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_nf = json.load(json_file_nf)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'flowEntropyDetectionNetFlow'
    MQTT_PASSWORD = 'flowEntropyDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        s=0
        #print(systemId, "Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print(systemId, "Bi-directional flow entropy detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("BidirectionalFlowEntropyDetectionNetFlow")
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


    flowEntropy = data["flowEntropy"]
    flowEntropyRate = data["flowEntropyRate"]
    numberOfFlows = data["numberOfFlows"]

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
    trueNegatives_r  = 0

    truePositives_nf = 0
    falsePositives_nf = 0
    falseNegatives_nf = 0
    trueNegatives_nf  = 0


    #Loop through all the flow records in the input file
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
            change = flowEntropy[i] - np.nanmean(flowEntropy[i-windowSize: i-1])
            change_r = flowEntropyRate[i] - np.nanmean(flowEntropyRate[i-windowSize: i-1])
            change_nf = numberOfFlows[i] - np.nanmean(numberOfFlows[i-windowSize: i-1])
            
            if change < 0 and change_r < 0:
                attackType = "Low-Rate"
            elif change_r < 0:
                attackType = "Flooding"
            else:
                attackType = ""
                
            simulateRealTime(datetime.now(), eTime[i], attackDate)
            if abs(change) > thresholdFlowEntropy:
                alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change),maxmin_flow["minimum"], maxmin_flow["maximum"]),
                    "Real_label": int(attack),
                    "Attack_type": attackType
                    }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

            if abs(change_r) > thresholdFlowEntropyRate:
                alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change_r),maxmin_flow_rate["minimum"], maxmin_flow_rate["maximum"]),
                    "Real_label": int(attack),
                    "Attack_type": attackType
                    }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

            if abs(change_nf) > thresholdNumberOfFlows:
                alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change_nf), maxmin_nf["minimum"], maxmin_nf["maximum"]),
                    "Real_label": int(attack),
                    "Attack_type": attackType
                    }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
            
            if abs(change) > thresholdFlowEntropy and attack:
                truePositives += 1
            elif abs(change) > thresholdFlowEntropy and not attack:
                falsePositives += 1
            elif abs(change) <= thresholdFlowEntropy and attack:
                falseNegatives +=1
            elif abs(change) <= thresholdFlowEntropy and not attack:
                trueNegatives += 1
            
            if abs(change_r) > thresholdFlowEntropyRate and attack:
                truePositives_r += 1
            elif abs(change_r) > thresholdFlowEntropyRate and not attack:
                falsePositives_r += 1
            elif abs(change_r) <= thresholdFlowEntropyRate and attack:
                falseNegatives_r += 1
            elif abs(change_r) <= thresholdFlowEntropyRate and not attack:
                trueNegatives_r += 1
            
            if abs(change_nf) > thresholdNumberOfFlows and attack:
                truePositives_nf += 1
            elif abs(change_nf) > thresholdNumberOfFlows and not attack:
                falsePositives_nf += 1
            elif abs(change_nf) <= thresholdNumberOfFlows and attack:
                falseNegatives_nf += 1
            elif abs(change_nf) <= thresholdNumberOfFlows and not attack:
                trueNegatives_nf += 1
        else:
            if attack:
                falseNegatives +=1
                falseNegatives_r += 1
                falseNegatives_nf += 1
            elif not attack:
                trueNegatives += 1
                trueNegatives_r += 1
                falseNegatives_nf += 1
    
    sleep(randrange(400))
    p = Path('Detections' + fileString)
    q = p / 'Entropy' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    r = p / 'Threshold' / 'NetFlow'
    if not r.exists():
        r.mkdir(parents=True)

    #Open files to write alerts to
    scores = open(str(q) + "/Scores.FlowEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    scores_r = open(str(q) + "/Scores.FlowEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    scores_nf = open(str(r) + "/Scores.NumberOfFlows."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    scores.write("TP,FP,FN,TN")
    scores_r.write("TP,FP,FN,TN")
    scores_nf.write("TP,FP,FN,TN")

    scores.write("\n"+ str(truePositives)+ "," + str(falsePositives)+ "," + str(falseNegatives)+ "," + str(trueNegatives))
    scores.close()

    scores_r.write("\n"+ str(truePositives_r)+ "," + str(falsePositives_r)+ "," + str(falseNegatives_r)+ "," + str(trueNegatives_r))
    scores_r.close()

    scores_nf.write("\n"+ str(truePositives_nf)+ "," + str(falsePositives_nf)+ "," + str(falseNegatives_nf)+ "," + str(trueNegatives_nf))
    scores_nf.close()