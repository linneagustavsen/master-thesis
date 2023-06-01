from pathlib import Path
import pandas as pd
import paho.mqtt.client as mqtt
from time import sleep
from random import randrange
from threading import Thread
import json
from datetime import timedelta

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
    def __init__(self, broker, port, inputTopic, outputTopic, attackDate):
        self.port = port
        self.broker = broker
        self.input = inputTopic
        self.output = outputTopic
        self.alertsIP ={}
        self.alertCounter = 0

        if attackDate == "08.03.23":
            self.fileString = "0803"
        elif attackDate == "17.03.23":
            self.fileString = "1703"
        elif attackDate == "24.03.23":
            self.fileString = "2403"

    def countElements(self, listOfElements):
        counter = {}
        for element in listOfElements:
            if element in counter:
                counter[element] += 1
            else:
                counter[element] = 1
        return counter

    def addAlertsIP(self, ip, interval, alert):
        if ip in self.alertsIP:
            if interval in self.getTimesAlertsIP(ip):
                self.alertsIP[ip][interval].append(alert)
            else:
                self.alertsIP[ip][interval]= [alert]
        else:
                self.alertsIP[ip] = {interval:[alert]}

    def getTimesAlertsIP(self, ip):
        return self.alertsIP[ip]
    
    def getAlertsIP(self, ip, interval):
        return self.alertsIP[ip][interval]
    
    def removeTimestampFromIP(self, ip, interval):
        del self.alertsIP[ip][interval]

    def correlateIPs(self, stime, etime, ip, payload):
        stime = pd.Timestamp(stime)
        etime = pd.Timestamp(etime)
        fuzzyStartTime = stime - timedelta(minutes = 15)
        interval = pd.Interval(fuzzyStartTime, etime, closed='both')

        if ip in self.alertsIP:
            exists = False
            existingTimes = []
            overlappingAlerts = 1
            gateways = [payload.get('Gateway')]
            deviation_scores = []
            real_labels = []
            attack_types = []
            removeTimes = []

            for time in self.getTimesAlertsIP(ip):
                if time.left < stime - timedelta(minutes = 15):
                    removeTimes.append(time)
                    continue

                if interval.overlaps(time):
                    exists = True
                    existingTimes.append(time)
                    alerts = self.getAlertsIP(ip, time)
                    overlappingAlerts += len(alerts)

                    for alert in alerts:
                        gateways.append(alert['Gateway'])
                        deviation_scores.append(alert["Deviation_score"])
                        real_labels.append(alert["Real_label"])
                        attack_types.append(alert["Attack_type"])
            
            for time in removeTimes:
                self.removeTimestampFromIP(ip, time)
                if time in existingTimes:
                    existingTimes.remove(time)

            if exists:
                for existingTime in existingTimes:
                    self.addAlertsIP(ip, existingTime, payload)
   
                if overlappingAlerts > 3:
                    
                    message = { 'sTime': stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                'eTime': etime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                'IP': ip,
                                'Gateways': list(set(gateways)),
                                'Deviation_scores': deviation_scores,
                                'Real_labels': self.countElements(real_labels),
                                'Attack_types': self.countElements(attack_types)
                                }
                    
                    self.mqtt_client.publish(self.output, json.dumps(message))
            else:
                self.addAlertsIP(ip, interval, payload)
        else:
            self.addAlertsIP(ip, interval, payload)

    """
        The MQTT commands are listened to and appropriate actions are taken for each.
    """
    def on_connect(self, client, userdata, flags, rc):
        print("Connected with result code "+str(rc))
        self.mqtt_client.subscribe(self.input)

    def on_publish(self, client, userdata, result):
        print("Correlation published to topic", self.output)
    
    def on_message(self, client, userdata, msg):
        self.alertCounter += 1
        print('Incoming message to topic {}'.format(msg.topic))
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
            #print(payload)
        except Exception as err:
            print('Message sent to topic {} had no valid JSON. Message ignored. {}'.format(msg.topic, err))
            return

        if payload.get('sTime') == "WRITE":
            p = Path('Detections' + self.fileString)
            q = p / 'Correlation' 
            if not q.exists():
                q.mkdir(parents=True)
            alertsFile = open(str(q) + "/NumberOfAlertsCorrelationIPs.csv", "a")
            alertsFile.write("NumberOfAlerts\n" + str(self.alertCounter))
            alertsFile.close()
        else:
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
        self.mqtt_client.on_publish = self.on_publish

        self.mqtt_client.connect(self.broker, self.port)
        try:
            thread = Thread(target=self.mqtt_client.loop_forever)
            thread.start()
            
        except:
            print("Interrupted")
            
            self.mqtt_client.disconnect()
