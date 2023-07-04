from datetime import timedelta,datetime
from pathlib import Path
import pickle
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import numpy as np
import paho.mqtt.client as mqtt
from time import sleep
from random import randrange
from HelperFunctions.AttackIntervals import inAttackInterval
import json

from HelperFunctions.SimulateRealTime import simulateRealTime

'''
    Detect anomalies based on a random forest classifier and write them to file
    Input:  trainingSet:    pandas dataframe, training data set
            testingSet:     pandas dataframe, testing data set
            systemId:       string, name of the system to collect and detct on  
            interval:       timedelta object, size of the sliding window which the detection is made on
            attackDate:     string, date of the attack the detection are made on
'''
def detectionRandomForestNetFlow(start, stop, systemId, interval, weight, attackDate):
    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'randomForestCombinedDetectionNetFlow'
    MQTT_PASSWORD = 'randomForestCombinedDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        s=0
        #print(systemId, "Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print(systemId, "Random forest combined detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("RandomForestCombinedDetectionNetFlow")
    #mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
    #mqtt_client.loop_start()

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
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')


    alertFile ="Calculations"+fileString+"/RandomForest/NetFlow/Alerts.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv"
    counter = 0
    countChunks = 0
    truePositives = 0
    falsePositives = 0
    for alerts in pd.read_csv(alertFile, chunksize=100):
        countChunks += 1
        sTime = pd.to_datetime(alerts["sTime"])
        eTime = pd.to_datetime(alerts["eTime"])

        '''srcPort = alerts["srcPort"]
        dstPort = alerts["dstPort"]
        protocol = alerts["protocol"]'''
        real_label = alerts["real_label"]

        for i in range(len(sTime)):
            isInAttackTime, attackTypeDuringThisTime = inAttackInterval(sTime[counter], eTime[counter], attackDate)
            sTime[counter] = sTime[counter].replace(tzinfo=None)
            eTime[counter] = eTime[counter].replace(tzinfo=None)
            if eTime[counter] > stopTime:
                break
            if sTime[counter] < startTime:
                counter += 1
                continue
            #simulateRealTime(datetime.now(), sTime[counter], attackDate)
            alert = {
                    "sTime": sTime[counter].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[counter].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": None,
                    "Real_label": int(real_label[counter]),
                    "Attack_type": "",
                    "Weight": weight
                }
            '''alert = {
                    "sTime": sTime[counter].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[counter].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "srcIP":testingMeasurements[counter][0],
                    "dstIP": testingMeasurements[counter][1],
                    "srcPort": srcPort[counter],
                    "dstPort": dstPort[counter],
                    "Protocol": protocol[counter],
                    "Deviation_score": None,
                    "Real_label": int(real_label[counter]),
                    "Attack_type": ""
                }'''
            #mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

            if real_label[counter]:
                truePositives +=1
                if isInAttackTime:
                    attackDict[attackTypeDuringThisTime]["TP"] += 1
            elif not real_label[counter]:
                falsePositives += 1
                if isInAttackTime:
                    attackDict[attackTypeDuringThisTime]["FP"] += 1
    
            counter += 1
        counter = 100*countChunks
    p = Path('Detections' + fileString)
    q = p / 'RandomForest' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    attackScores = open(str(q) + "/ScoresAttacks.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json", "w")
    json.dump(attackDict,attackScores)
    attackScores.close()

    scores = open(str(q) + "/Scores.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    scores.write("TP,FP")
    scores.write("\n"+ str(truePositives)+ "," + str(falsePositives))
    scores.close()