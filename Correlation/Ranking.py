from datetime import datetime, timedelta
from numpy import mean
import pandas as pd
from Correlation.NetworkGraph import NetworkGraph
import paho.mqtt.client as mqtt
from threading import Thread
import json

#Parameters for the MQTT connection
MQTT_BROKER = 'mosquitto'
MQTT_PORT = 1883
MQTT_USER = 'aggregation'
MQTT_PASSWORD = 'aggregationPass'
MQTT_TOPIC_INPUT = 'detections/correlation'
MQTT_TOPIC_OUTPUT = 'detections/ranking'

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

    def rank(self, stime, etime, gateways, deviation_scores, real_labels, attack_types):
        if ranking > 0:
            newRanking = []
            i = 0
            for position, alert in ranking:
                if alert['sTime'] > stime - timedelta(minutes=15):
                    if alert['deviation_score'] < mean(deviation_scores):
                        newAlert = {
                        "sTime": stime,
                        "eTime": etime,
                        "Gateways": gateways,
                        "Deviation_scores": deviation_scores,
                        "Real_labels": real_labels,
                        "Attack_type": attack_types
                        }
                        newRanking[i] = newAlert
                        i+=1
                        newRanking[i] = alert
                    else:
                        newRanking[i] = alert
                        i+=1
        else:
            newAlert = {
                    "sTime": stime,
                    "eTime": etime,
                    "Gateways": gateways,
                    "Deviation_scores": mean(deviation_scores),
                    "Real_labels": real_labels,
                    "Attack_type": attack_types
                    }
            ranking.append({0: newAlert})
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

graph = NetworkGraph()
ranking = Ranking(MQTT_BROKER, MQTT_PORT, MQTT_TOPIC_INPUT, MQTT_TOPIC_OUTPUT, graph)
ranking.start()