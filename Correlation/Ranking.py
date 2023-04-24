from datetime import datetime, timedelta
from pathlib import Path
from numpy import mean
import pandas as pd
from Correlation.NetworkGraph import NetworkGraph
import paho.mqtt.client as mqtt
from threading import Thread
import json

#Parameters for the MQTT connection
MQTT_BROKER = 'localhost'
MQTT_PORT = 1883
MQTT_USER = 'aggregation'
MQTT_PASSWORD = 'aggregationPass'
MQTT_TOPIC_INPUT = 'detections/correlation'
MQTT_TOPIC_OUTPUT = 'detections/ranking'
p = Path('Detections')
q = p / 'Correlation' 
if not q.exists():
    q.mkdir(parents=True)
rankingFile = open(str(q) + "/Ranking.csv", "a")
rankingFile.write("Position,sTime,eTime,Gateways,Deviation_score,Attack_type,Real_labels")

class Ranking:
    """
        The class is initialized with data fields and database dictionaries.
    """
    def __init__(self, broker, port, inputTopic, outputTopic, graph):
        self.port = port
        self.broker = broker
        self.input = inputTopic
        self.output = outputTopic
        self.graph = graph
        self.ranking = []
        
    def writeRankingToFile(self):
        line = ""
        position = 0
        for alert in self.ranking:
            line += "\n"
            line += str(position) + ","
            line += alert['sTime'].strftime("%Y-%m-%dT%H:%M:%SZ") + ","
            line += alert['eTime'].strftime("%Y-%m-%dT%H:%M:%SZ") + ","
            line += str(alert['Gateways']) + ","
            line += str(alert['Deviation_score']) + ","
            line += str(alert['Attack_type']) + ","
            line += str(alert['Real_labels'])
            position +=1
        line += "\n"
        rankingFile.write(line)

    def rank(self, stime, etime, gateways, deviation_scores, real_labels, attack_types):
        stime = datetime.strptime(stime, "%Y-%m-%dT%H:%M:%SZ")
        etime = datetime.strptime(etime, "%Y-%m-%dT%H:%M:%SZ")
        if len(self.ranking) > 0:
            newRanking = []
            i = 0
            print("\nRANK")
            print(self.ranking)
            
            for alert in self.ranking:
                print(alert)
                if alert['sTime'] > stime - timedelta(minutes=15):
                    newRanking.append(alert)

            newAlert = {
                        "sTime": stime,
                        "eTime": etime,
                        "Gateways": gateways,
                        "Deviation_score": mean(deviation_scores),
                        "Real_labels": real_labels,
                        "Attack_type": attack_types
                        }
            print("\nNew")
            newRanking.append(newAlert)
            newRanking = sorted(newRanking, key=lambda x: x["Deviation_score"], reverse=True)
            print(newRanking)
            self.ranking = newRanking
        else:
            newAlert = {
                    "sTime": stime,
                    "eTime": etime,
                    "Gateways": gateways,
                    "Deviation_score": mean(deviation_scores),
                    "Real_labels": real_labels,
                    "Attack_type": attack_types
                    }
            self.ranking.append(newAlert)
        self.writeRankingToFile()
        
    """
        The MQTT commands are listened to and appropriate actions are taken for each.
    """
    def on_connect(self, client, userdata, flags, rc):
        print("Connected with result code "+str(rc))
        self.mqtt_client.subscribe(self.input)

    def on_publish(self, client, userdata, result):
        print("Aggregation published to topic", self.input)
    
    def on_message(self, client, userdata, msg):
        print('Incoming message to topic {}'.format(msg.topic))
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
            print(payload)
        except Exception as err:
            print('Message sent to topic {} had no valid JSON. Message ignored. {}'.format(msg.topic, err))
            return

        stime = payload.get('sTime')
        etime = payload.get('eTime')
        gateways = payload.get('Gateways')
        deviation_scores = payload.get('Deviation_scores')
        real_labels = payload.get('Real_labels')
        attack_types = payload.get('Attack_type')

        self.rank(stime, etime, gateways, deviation_scores, real_labels, attack_types)

    def start(self):
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_message = self.on_message
        self.mqtt_client.on_connect = self.on_connect
        
        self.mqtt_client.connect(self.broker, self.port)
        try:
            thread = Thread(target=self.mqtt_client.loop_forever)
            thread.start()
            
        except KeyboardInterrupt:
            print("Interrupted")
            self.mqtt_client.disconnect()