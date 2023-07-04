import json
from pathlib import Path
import pandas as pd
from silk import *
from datetime import datetime
from HelperFunctions.IsAttack import *
import paho.mqtt.client as mqtt
from time import sleep
from random import randrange
from HelperFunctions.AttackIntervals import inAttackInterval

from HelperFunctions.SimulateRealTime import simulateRealTime

'''
    Calculates the number of Xmas packets in a flow and writes all values over 1 to file
    Input:  silkFile:   string, file with flow records sorted on time
            start:      string, start time of detection 
            stop:       string, stop time of detection 
            systemId:   string, name of the system to calculate on
            attackDate: string, date of the attack the calculations are made on
'''
def xmasCalculation(start, stop, systemId, weight, attackDate):

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'synDetectionNetFlow'
    MQTT_PASSWORD = 'synDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        s=0
        #print(systemId, "Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print(systemId, "Xmas detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("SYNDetectionNetFlow")
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
    counter = 0
    countChunks = 0
    for data in pd.read_csv("Calculations"+fileString+"/Threshold/NetFlow/Xmas.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", chunksize=100):
        countChunks += 1
        sTime = pd.to_datetime(data["sTime"])
        eTime = pd.to_datetime(data["eTime"])

        '''srcPort = data["srcPort"]
        dstPort = data["dstPort"]
        protocol = data["protocol"]'''
        real_label = data["real_label"]

        truePositives = 0
        falsePositives = 0

        startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
        stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
        #Loop through all the flow records in the input file
        for i in range(len(sTime)):
            isInAttackTime, attackTypeDuringThisTime = inAttackInterval(sTime[counter], eTime[counter], attackDate)
            sTime[counter] = sTime[counter].replace(tzinfo=None)
            eTime[counter] = eTime[counter].replace(tzinfo=None)
            if eTime[counter] > stopTime:
                break
            if sTime[counter] < startTime:
                counter += 1
                continue

            attack = real_label[counter]
            simulateRealTime(datetime.now(), sTime[counter], attackDate)
            alert = {
                    "sTime": sTime[counter].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[counter].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": None,
                    "Real_label": int(attack),
                    "Attack_type": "Xmas",
                    "Weight": weight
                    }
            '''alert = {
                    "sTime": sTime[counter].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[counter].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": None,
                    "srcIP": int(rec.sip),
                    "dstIP": int(rec.dip),
                    "srcPort": int(srcPort[counter]),
                    "dstPort": int(dstPort[counter]),
                    #"Protocol": int(protocol[counter]),
                    "Real_label": int(attack),
                    "Attack_type": "Xmas"
                    }'''
            mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
            if attack:
                truePositives += 1
                if isInAttackTime:
                    attackDict[attackTypeDuringThisTime]["TP"] += 1
            elif not attack:
                falsePositives += 1
                if isInAttackTime:
                    attackDict[attackTypeDuringThisTime]["FP"] += 1
            counter += 1
        counter = 100*countChunks
    #sleep(randrange(400))
    p = Path('Detections' + fileString)
    q = p / 'Threshold' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    #Open file to write alerts to
    scores = open(str(q) + "/Scores.Xmas.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    scores.write("TP,FP")
    scores.write("\n"+ str(truePositives)+ "," + str(falsePositives))
    scores.close()

    attackScores = open(str(q) + "/ScoresAttacks.Xmas.attack."+str(attackDate)+ "."+str(systemId)+ ".json", "w")
    json.dump(attackDict,attackScores)
    attackScores.close()