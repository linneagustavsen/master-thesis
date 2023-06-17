from pathlib import Path
import pandas as pd
from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime,timedelta
import numpy as np
import paho.mqtt.client as mqtt
from time import sleep
from random import randrange
from HelperFunctions.AttackIntervals import inAttackInterval
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
            thresholdBytes:                 float, values over this threshold will cause an alert
            attackDate:                     string, date of the attack the calculations are made on
'''
def detectionBytesNetFlow(start, stop, systemId, frequency, interval, windowSize, thresholdBytes, weight, attackDate):

    p = Path('NetFlow')
    q = p / 'Threshold' / 'Calculations'
    if not q.exists():
        q = Path('Threshold')
        q = q / 'Calculations'
    json_file_bytes = open(str(q) + "/MinMaxValues/MinMax.bytes."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_bytes = json.load(json_file_bytes)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'bytesDetectionNetFlow'
    MQTT_PASSWORD = 'bytesDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        s=0
        #print(systemId, "Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print(systemId, "Bytes detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("BytesDetectionNetFlow")
    #mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
    mqtt_client.loop_start()

    if attackDate == "08.03.23":
        fileString = "0803"
        attackDict = {"SYN Flood":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "SlowLoris": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "Ping Flood": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "R.U.D.Y":{"TP":0, "FP":0, "TN": 0, "FN": 0}}
    elif attackDate == "17.03.23":
        fileString = "1703"
        attackDict = {"SYN Flood":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "SlowLoris": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "Ping Flood": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "R.U.D.Y":{"TP":0, "FP":0, "TN": 0, "FN": 0}}
    elif attackDate == "24.03.23":
        fileString = "2403"
        attackDict = {"UDP Flood":{"TP":0, "FP":0, "TN": 0, "FN": 0},
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
    data = pd.read_csv("Calculations"+fileString+"/Entropy/NetFlow/Metrics."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    sTime = pd.to_datetime(data["sTime"])
    eTime = pd.to_datetime(data["eTime"])


    bytesArray = data["numberOfBytes"]

    if attackDate != "24.03.23":
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
    else:
        real_labels = data["real_label"]
    truePositives = 0
    falsePositives = 0
    falseNegatives = 0
    trueNegatives  =0

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

        if attackDate != "24.03.23":
            attack = False
            for timeInterval in attackIntervals:
                if sTime[i] in timeInterval or eTime[i] in timeInterval:
                    attack = True
        else:
            attack = real_labels[i]
        if i >=windowSize:
            change = bytesArray[i] - np.nanmean(bytesArray[i-windowSize: i-1])
            
            simulateRealTime(datetime.now(), eTime[i], attackDate)
            if abs(change) > thresholdBytes:
                alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change), maxmin_bytes["minimum"], maxmin_bytes["maximum"]),
                    "Real_label": int(attack),
                    "Attack_type": "Flooding",
                    "Weight": weight,
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
                
            if abs(change) > thresholdBytes and isInAttackTime and attack:
                attackDict[attackTypeDuringThisTime]["TP"] += 1
            elif abs(change) > thresholdBytes and isInAttackTime and not attack:
                attackDict[attackTypeDuringThisTime]["FP"] += 1
            elif abs(change) <= thresholdBytes and isInAttackTime and attack:
                attackDict[attackTypeDuringThisTime]["FN"] +=1
            elif abs(change) <= thresholdBytes and isInAttackTime and not attack:
                attackDict[attackTypeDuringThisTime]["TN"] += 1
        else:
            if attack:
                falseNegatives += 1
            elif not attack:
                trueNegatives += 1

            if attack and isInAttackTime:
                attackDict[attackTypeDuringThisTime]["FN"] +=1
            elif not attack and isInAttackTime:
                attackDict[attackTypeDuringThisTime]["TN"] += 1
    #sleep(randrange(400))
    p = Path('Detections' + fileString)
    q = p / 'Threshold' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    #Open file to write alerts to
    scores = open(str(q) + "/Scores.Bytes."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    scores.write("TP,FP,FN,TN")
    scores.write("\n"+ str(truePositives)+ "," + str(falsePositives)+ "," + str(falseNegatives)+ "," + str(trueNegatives))
    scores.close()

    attackScores = open(str(q) + "/ScoresAttacks.Bytes."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json", "w")
    json.dump(attackDict,attackScores)
    attackScores.close()