from pathlib import Path
import pandas as pd
from Correlation.NetworkGraph import NetworkGraph
import paho.mqtt.client as mqtt
from time import sleep
from random import randrange
import networkx as nx
from threading import Thread
import json
from datetime import datetime, timedelta
from datetime import date

from HelperFunctions.InformationDistance import informationDistance

#Parameters for the MQTT connection
MQTT_BROKER = 'localhost'
MQTT_PORT = 1883
MQTT_USER = 'correlation'
MQTT_PASSWORD = 'correlationPass'
MQTT_TOPIC_INPUT = 'detections/aggregation/distribution'
MQTT_TOPIC_OUTPUT = 'detections/correlation'

"""
    This class is for correlating alerts
"""
class Correlation_Distribution:
    def __init__(self, broker, port, inputTopic, outputTopic, graph, attackDate):
        self.port = port
        self.broker = broker
        self.input = inputTopic
        self.output = outputTopic
        self.graph = graph
        self.alertCounter = 0
        self.truePositivesIn = 0
        self.falsePositivesIn = 0
        self.truePositivesOut = 0
        self.falsePositivesOut = 0

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
        if '0' or '1' in counter:
            if counter['0'] > counter['1']:
                self.falsePositivesOut += 1
            elif counter['0'] < counter['1']:
                self.truePositivesOut += 1
        return counter
    
    def addElementToCounterDict(self, element, counterDict):
        if element in counterDict:
            counterDict[element] += 1
        else:
            counterDict[element] = 1
        return counterDict
    
    def decodeAlertDB(self, alertDB):
        newAlertDB = {}
        for gateway in alertDB:
            newAlertDB[gateway] = {}
            for time in alertDB[gateway]:
                start = pd.Timestamp(time.split(",")[0])
                end = pd.Timestamp(time.split(",")[1])
                interval = pd.Interval(start, end, closed='both')
                newAlertDB[gateway][interval] = alertDB[gateway][time]
        return newAlertDB
    
    def removeTimestampFromCorrelation(self, interval):
        del self.alertsCorrelated[interval]

    def addAlertToExistingTimestamp(self, interval, alert):
        if interval in self.alertsCorrelated:
            self.alertsCorrelated[interval].append(alert)
        else:
            self.alertsCorrelated[interval] = alert

    def correlateDistribution(self, stime, etime, gateway, distributions, deviation_scores, real_labels, attack_types, alertDB):
        timeExists = False
        gateways = [gateway]
        stime = pd.Timestamp(stime)
        etime = pd.Timestamp(etime)
        fuzzyStartTime = stime - timedelta(seconds = 2)
        interval = pd.Interval(fuzzyStartTime, etime, closed='both')

        for otherGateway in self.graph.G:
            if otherGateway == gateway:
                continue

            if nx.shortest_path_length(self.graph.G, gateway, otherGateway) < 4:
                for time in alertDB[otherGateway]:
                    if interval.overlaps(time):
                        for distribution in distributions:
                            alerts = alertDB[otherGateway][time]

                            for alert in alerts:
                                print(alert["Packet_size_distribution"])
                                if informationDistance(10, distribution, alert["Packet_size_distribution"]) < 2:
                                    timeExists = True
                                    gateways.append(otherGateway)
                                    deviation_scores.append(alert["Deviation_score"])
                                    real_labels.append(alert["Real_label"])
                                    attack_types.append(alert["Attack_type"])

        if timeExists:
            message = {
                    "sTime": stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": etime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateways": list(set(gateways)),
                    "Deviation_scores": deviation_scores,
                    "Real_labels": self.countElements(real_labels),
                    "Attack_types": self.countElements(attack_types)
                    }
            
            print("\nPublished message to topic", self.output)
            print(message)
            print("\n")
            self.mqtt_client.publish(self.output, json.dumps(message))


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
            alertsFile = open(str(q) + "/NumberOfAlertsCorrelationDistribution.csv", "a")
            alertsFile.write("NumberOfAlertsIn,TPin,FPin,TPout,FPout\n" + str(self.alertCounter) +"," + str(self.truePositivesIn) + ","+ str(self.falsePositivesIn)+"," + str(self.truePositivesOut) + ","+ str(self.falsePositivesOut))
            alertsFile.close()

        else:
            stime = payload.get('sTime')
            etime = payload.get('eTime')
            gateway = payload.get('Gateway')
            deviation_scores = payload.get('Deviation_scores')
            real_labels = payload.get('Real_labels')
            attack_types = payload.get('Attack_types')
            alertDB = payload.get('alertDB')
            alertDB = self.decodeAlertDB(alertDB)
            distributions = payload.get('Packet_size_distributions')

            

            self.correlateDistribution(stime, etime, gateway, distributions, deviation_scores, real_labels, attack_types, alertDB)
            falseLabels = 0
            trueLabels = 0
            for label in real_labels:
                if label == '1':
                    trueLabels += 1
                elif label == '0':
                    falseLabels += 1
            if falseLabels > trueLabels:
                self.falsePositivesIn += 1
            elif falseLabels < trueLabels:
                self.truePositivesIn += 1

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
