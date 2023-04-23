import pandas as pd
from Correlation.NetworkGraph import NetworkGraph
import paho.mqtt.client as mqtt
import networkx as nx
from threading import Thread
import json
from datetime import datetime, timedelta
from datetime import date

#Parameters for the MQTT connection
MQTT_BROKER = 'mosquitto'
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

    def addAlertToExistingTimestampAlertsIP(self, ip, interval, alert):
        self.alertsIP[ip][interval].append(alert)

    def addTimestampAndAlertToAlertsIP(self, ip, interval, alert):
        self.alertsIP[ip][interval] = [alert]

    def getTimesAlertsIP(self, ip):
        return self.alertsIP[ip]
    
    def getAlertsIP(self, ip, interval):
        return self.alertsIP[ip][interval]

    def correlateIPs(self, stime, etime, ip, payload):
        if ip in self.alertsIP:

            stime = pd.Timestamp(stime)
            etime = pd.Timestamp(etime)
            fuzzyStartTime = stime - timedelta(minutes = 15)
            interval = pd.Interval(fuzzyStartTime, etime, closed='left')
            exists = False
            overlappingAlerts = 0
            deviation_scores = []
            real_labels = []
            attack_types = []

            for time, alerts in self.getTimesAlertsIP(ip):
                if interval.overlaps(time):
                    exists = True
                    overlappingAlerts += len(alerts)
                    for alert in alerts:
                        deviation_scores.append(alert["Deviation_score"])
                        real_labels.append(alert["Real_label"])
                        attack_types.append(alert["Attack_type"])
            if exists:
                self.addAlertToExistingTimestampAlertsIP(ip, interval, payload)
                if overlappingAlerts > 10:
                    message = { 'sTime': stime,
                                'eTime': etime,
                                'IP': ip,
                                'Deviation_scores': deviation_scores,
                                'Real_labels': real_labels,
                                'Attack_types': attack_types
                                }
                    self.mqtt_client.publish(self.outputIPs, json.dumps(message))
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

correlation = Correlation_IPs(MQTT_BROKER, MQTT_PORT, MQTT_TOPIC_INPUT, MQTT_TOPIC_OUTPUT)
correlation.start()