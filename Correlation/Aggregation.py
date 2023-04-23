from datetime import datetime, timedelta

import pandas as pd
from Correlation.NetworkGraph import NetworkGraph
from Correlation.statemachine import Correlation_Sender
import paho.mqtt.client as mqtt
from threading import Thread
import json

#Parameters for the MQTT connection
MQTT_BROKER = 'mosquitto'
MQTT_PORT = 1883
MQTT_USER = 'aggregation'
MQTT_PASSWORD = 'aggregationPass'
MQTT_TOPIC_INPUT = 'detections/modules/#'
MQTT_TOPIC_OUTPUT_TIME = 'detections/aggregation/time'
MQTT_TOPIC_OUTPUT_IPS = 'detections/aggregation/ips'

class Aggregation:
    """
        The class is initialized with data fields and database dictionaries.
    """
    def __init__(self, broker, port, inputTopic, outputTopicTime, outputTopicIPs, graph):
        self.port = port
        self.broker = broker
        self.input = inputTopic
        self.outputTime = outputTopicTime
        self.outputIPs = outputTopicIPs
        self.graph = graph

        self.alertDB = {}
        for node in self.graph:
            self.alertDB[node] = {}

    def addAlertToExistingTimestampGraph(self, gateway, interval, alert):
        self.alertDB[gateway][interval].append(alert)
    
    def addTimestampToGraph(self, gateway, interval, alert):
        self.alertDB[gateway][interval] = [alert]

    def removeTimestampFromGraph(self, gateway, interval):
        del self.alertDB[gateway][interval]

    def getTimes(self, gateway):
        return self.alertDB[gateway]

    def getAlerts(self, gateway, interval):
        return self.alertDB[gateway][interval]


    def aggregateTime(self, stime, etime, gateway, payload):
        stime = pd.Timestamp(stime)
        etime = pd.Timestamp(etime)
        fuzzyStartTime = stime - timedelta(seconds = 30)
        interval = pd.Interval(fuzzyStartTime, etime, closed='left')
        exists = False
        overlappingAlerts = 0
        deviation_scores = []
        real_labels = []
        attack_types = []

        for time, alerts in self.getTimes(gateway):
            if interval.overlaps(time):
                exists = True
                overlappingAlerts += len(alerts)
                for alert in alerts:
                    deviation_scores.append(alert["Deviation_score"])
                    real_labels.append(alert["Real_label"])
                    attack_types.append(alert["Attack_type"])
        if exists:
            self.addAlertToExistingTimestampGraph(gateway, interval, payload)
            if overlappingAlerts > 3:
                
                message = {'sTime': stime,
                        'eTime': etime,
                        'Gateway': gateway,
                        'Deviation_scores': deviation_scores,
                        'Real_labels': real_labels,
                        'Attack_types': attack_types,
                        'alertDB': self.alertDB}
                
                self.mqtt_client.publish(self.outputTime, json.dumps(message))
        else:
            self.addTimestampToGraph(gateway, interval, payload)


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
        gateway = payload.get('Gateway')

        self.aggregateTime(stime, etime, gateway, payload)
        
        try:
            srcIP = payload.get('srcIP')
            dstIP = payload.get('dstIP')
            self.mqtt_client.publish(self.outputIPs, msg)

        except Exception as err:
            print('Message sent to topic {} had no IP addresses. {}'.format(msg.topic, err))
            return

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
aggregation = Aggregation(MQTT_BROKER, MQTT_PORT, MQTT_TOPIC_INPUT, MQTT_TOPIC_OUTPUT_TIME, MQTT_TOPIC_OUTPUT_IPS, graph)
aggregation.start()