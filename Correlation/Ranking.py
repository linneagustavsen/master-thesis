from datetime import datetime, timedelta
from pathlib import Path
import statistics
import numpy as np
import pandas as pd
from Correlation.NetworkGraph import NetworkGraph
import paho.mqtt.client as mqtt
from time import sleep
from random import randrange
from threading import Thread
import json

#Parameters for the MQTT connection
MQTT_BROKER = 'localhost'
MQTT_PORT = 1883
MQTT_USER = 'aggregation'
MQTT_PASSWORD = 'aggregationPass'
MQTT_TOPIC_INPUT = 'detections/correlation'
MQTT_TOPIC_OUTPUT = 'detections/ranking'

class Ranking:
    """
        The class is initialized with data fields and database dictionaries.
    """
    def __init__(self, broker, port, inputTopic, outputTopic, graph, attackDate):
        self.port = port
        self.broker = broker
        self.input = inputTopic
        self.output = outputTopic
        self.graph = graph
        self.ranking = []
        self.alertCounter = 0

        if attackDate == "08.03.23":
            self.fileString = "0803"
        elif attackDate == "17.03.23":
            self.fileString = "1703"
        elif attackDate == "24.03.23":
            self.fileString = "2403"
        
    def writeRankingToFile(self):
        p = Path('Detections' + self.fileString)
        q = p / 'Correlation' 
        if not q.exists():
            q.mkdir(parents=True)
        rankingFile = open(str(q) + "/RankingStdev.csv", "a")
        rankingFile.write("Position,sTime,eTime,Gateways,Deviation_score,Attack_type,Real_labels")
        line = ""
        position = 0
        for alert in self.ranking:
            line += "\n"
            line += str(position) + ","
            line += alert['sTime'].strftime("%Y-%m-%dT%H:%M:%SZ") + ","
            line += alert['eTime'].strftime("%Y-%m-%dT%H:%M:%SZ") + ","
            line += str(alert['Gateways']) + ","
            line += str(alert['Deviation_score']) + ","
            line += str(alert['Attack_types']) + ","
            line += str(alert['Real_labels'])
            position +=1
        line += "\n"
        line += "\n"
        rankingFile.write(line)
        rankingFile.close()


    def sortByAttackType(self, values):
        def priority_getter(value):
            priority = {
                "Flooding": 1,
                "ICMP Flood": 2,
                "SYN Flood": 3,
                "Same protocol": 4,
                "Xmas": 5,
                "Low-Rate": 6,
                "Different protocols": 7, 
                "": 8
            }
        
            highestKey = max(value["Attack_types"], key= lambda x: value["Attack_types"][x])

            if highestKey == "" and len(value["Attack_types"]) > 1:
                newValue = dict((i,value["Attack_types"][i]) for i in value["Attack_types"] if i!="")
                highestKey = max(newValue, key= lambda x: newValue[x])
            
            return priority.get(highestKey)

        return sorted(values, key=priority_getter)

    def rank(self, stime, etime, gateways, deviation_scores, real_labels, attack_types):
        deviation_scores = list(filter(lambda x: x is not None, deviation_scores))

        stime = datetime.strptime(stime, "%Y-%m-%dT%H:%M:%SZ")
        etime = datetime.strptime(etime, "%Y-%m-%dT%H:%M:%SZ")

        if len(self.ranking) > 0:
            newRanking = []
            
            for alert in self.ranking:
                if alert['sTime'] > stime - timedelta(minutes=15):
                    newRanking.append(alert)
            if len(deviation_scores) > 2:
                newAlert = {
                            "sTime": stime,
                            "eTime": etime,
                            "Gateways": gateways,
                            "Deviation_score": {"mean": np.nanmean(deviation_scores), "standard_deviation": statistics.stdev(deviation_scores)},
                            "Real_labels": real_labels,
                            "Attack_types": attack_types
                            }
            else:
                newAlert = {
                            "sTime": stime,
                            "eTime": etime,
                            "Gateways": gateways,
                            "Deviation_score": {"mean": np.nanmean(deviation_scores)},
                            "Real_labels": real_labels,
                            "Attack_types": attack_types
                            }

            newRanking.append(newAlert)
            newRanking = sorted(newRanking, key=lambda x: x["Deviation_score"]["mean"], reverse=True)
            newRanking = self.sortByAttackType(newRanking)
            self.ranking = newRanking
        else:
            if len(deviation_scores) > 2:
                newAlert = {
                        "sTime": stime,
                        "eTime": etime,
                        "Gateways": gateways,
                        "Deviation_score": {"mean": np.nanmean(deviation_scores), "standard_deviation": statistics.stdev(deviation_scores)},
                        "Real_labels": real_labels,
                        "Attack_types": attack_types
                        }
            else:
                newAlert = {
                        "sTime": stime,
                        "eTime": etime,
                        "Gateways": gateways,
                        "Deviation_score": {"mean": np.nanmean(deviation_scores)},
                        "Real_labels": real_labels,
                        "Attack_types": attack_types
                        }
            self.ranking.append(newAlert)
        self.writeRankingToFile()
        print("Wrote ranking to file")
        
    """
        The MQTT commands are listened to and appropriate actions are taken for each.
    """
    def on_connect(self, client, userdata, flags, rc):
        print("Connected with result code "+str(rc))
        self.mqtt_client.subscribe(self.input)

    def on_publish(self, client, userdata, result):
        print("Ranking published to topic", self.output)
    
    def on_message(self, client, userdata, msg):
        self.alertCounter += 1
        print('Incoming message to topic {}'.format(msg.topic))
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
        except Exception as err:
            print('Message sent to topic {} had no valid JSON. Message ignored. {}'.format(msg.topic, err))
            return
        
        if payload.get('sTime') == "WRITE":
            p = Path('Detections' + self.fileString)
            q = p / 'Correlation' 
            if not q.exists():
                q.mkdir(parents=True)
            alertsFile = open(str(q) + "/NumberOfAlertsRanking.csv", "a")
            alertsFile.write("NumberOfAlerts\n" + str(self.alertCounter))
            alertsFile.close()
        else:
            stime = payload.get('sTime')
            etime = payload.get('eTime')
            gateways = payload.get('Gateways')
            deviation_scores = payload.get('Deviation_scores')
            real_labels = payload.get('Real_labels')
            attack_types = payload.get('Attack_types')

            self.rank(stime, etime, gateways, deviation_scores, real_labels, attack_types)

    def start(self):
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_message = self.on_message
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_publish = self.on_publish
        
        self.mqtt_client.connect(self.broker, self.port)
        try:
            thread = Thread(target=self.mqtt_client.loop_forever)
            thread.start()
            
        except:
            print("Interrupted")
            
            self.mqtt_client.disconnect()