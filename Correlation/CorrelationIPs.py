import pandas as pd
from Correlation.NetworkGraph import NetworkGraph
import paho.mqtt.client as mqtt
import networkx as nx
from threading import Thread
import json
from datetime import datetime, timedelta
from datetime import date

#Parameters for the MQTT connection
MQTT_BROKER = 'localhost'
MQTT_PORT = 1883
MQTT_USER = 'correlation'
MQTT_PASSWORD = 'correlationPass'
MQTT_TOPIC_INPUT = 'detections/aggregation/ips'
MQTT_TOPIC_OUTPUT = 'detections/correlation'

"""
    This class is for correlating alerts
"""
class Correlation_IPs:
    def __init__(self, broker, port, inputTopic, outputTopic):
        self.port = port
        self.broker = broker
        self.input = inputTopic
        self.output = outputTopic
        self.alertsIP ={}

    def addAlertsIP(self, ip, interval, alert):
        self.alertsIP[ip] = {interval:[alert]}

    def addTimestampAndAlertToAlertsIP(self, ip, interval, alert):
        if interval in self.getTimesAlertsIP(ip):
            self.alertsIP[ip][interval].append(alert)
        else:
            self.alertsIP[ip][interval] = [alert]

    def getTimesAlertsIP(self, ip):
        return self.alertsIP[ip]
    
    def getAlertsIP(self, ip, interval):
        return self.alertsIP[ip][interval]

    def correlateIPs(self, stime, etime, ip, payload):
        stime = pd.Timestamp(stime)
        etime = pd.Timestamp(etime)
        fuzzyStartTime = stime - timedelta(minutes = 15)
        interval = pd.Interval(fuzzyStartTime, etime, closed='left')
        if ip in self.alertsIP:
            exists = False
            overlappingAlerts = 0
            deviation_scores = []
            real_labels = []
            attack_types = []

            for time in self.getTimesAlertsIP(ip):
                if interval.overlaps(time):
                    exists = True
                    alerts = self.getAlertsIP(ip, time)
                    overlappingAlerts += len(alerts)
                    for alert in alerts:
                        deviation_scores.append(alert["Deviation_score"])
                        real_labels.append(alert["Real_label"])
                        attack_types.append(alert["Attack_type"])
            if exists:
                self.addTimestampAndAlertToAlertsIP(ip, interval, payload)
                if overlappingAlerts > 10:
                    labels = {}
                    for element in real_labels:
                        if element in labels:
                            labels[element] += 1
                        else:
                            labels[element] = 1
                    message = { 'sTime': stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                'eTime': etime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                'IP': ip,
                                'Deviation_scores': deviation_scores,
                                'Real_labels': labels,
                                'Attack_types': list(set(attack_types))
                                }
                    self.mqtt_client.publish(self.output, json.dumps(message))
            else:
                self.addTimestampAndAlertToAlertsIP(ip, interval, payload)
        else:
            self.addAlertsIP(ip, interval, payload)

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
        srcIP = payload.get('srcIP')
        dstIP = payload.get('dstIP')

        self.correlateIPs(stime, etime, srcIP, payload)
        self.correlateIPs(stime, etime, dstIP, payload)

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
