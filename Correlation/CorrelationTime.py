from pathlib import Path
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
MQTT_TOPIC_INPUT = 'detections/aggregation/time'
MQTT_TOPIC_OUTPUT = 'detections/correlation'

"""
    This class is for correlating alerts
"""
class Correlation_Time:
    def __init__(self, broker, port, inputTopic, outputTopic, graph):
        self.port = port
        self.broker = broker
        self.input = inputTopic
        self.output = outputTopic
        self.graph = graph
        self.alertsCorrelated = {}
        self.alertCounter = 0

    def countElements(self, listOfElements):
        counter = {}
        for element in listOfElements:
            if element in counter:
                counter[element] += 1
            else:
                counter[element] = 1
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

    def correlateTime(self, stime, etime, gateway, deviation_scores, real_labels, attack_types, alertDB):
        #for gateway, timestamps in payload:
            #If gateway1 is close to gateway2 and they have the same fuzzy timestamps
                #look at attack types
                #(look at IPs, ports, protocol)
                #If they are the same
                    #generate an alert for that time, that attack type, and the highest deviation score (or the mean)
                    #send the alert to the alert ranking

        timeExists = False
        existsCorrelated = False
        existingTimes = []
        removeTimes = []
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
                        timeExists = True
                        gateways.append(otherGateway)
                        alerts = alertDB[otherGateway][time]

                        for alert in alerts:
                            deviation_scores.append(alert["Deviation_score"])
                            real_labels.append(alert["Real_label"])
                            attack_types.append(alert["Attack_type"])

        '''for time in self.alertsCorrelated:
            if time.left < stime - timedelta(minutes=15):
                removeTimes.append(time)
                continue

            if interval.overlaps(time):
                existsCorrelated = True
                existingTimes.append(time)
                alerts = self.alertsCorrelated[time]

                for alert in alerts:
                    gateways.extend(alert['Gateways'])
                    deviation_scores.extend(alert["Deviation_scores"])
                    real_labels.extend(alert["Real_labels"])
                    attack_types.extend(alert["Attack_types"])'''

        '''for time in removeTimes:
            #self.removeTimestampFromCorrelation(time)
            if time in existingTimes:
                    existingTimes.remove(time)'''

        alert = {
                    "sTime": stime,
                    "eTime": etime,
                    "Gateways": gateways,
                    "Deviation_scores": deviation_scores,
                    "Real_labels": real_labels,
                    "Attack_types": attack_types
                    }

        if timeExists or existsCorrelated:

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

        '''if existsCorrelated:
            for existingTime in existingTimes:
                self.addAlertToExistingTimestamp(existingTime, alert)
        else:
            self.alertsCorrelated[interval] = [alert]'''

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

        stime = payload.get('sTime')
        etime = payload.get('eTime')
        gateway = payload.get('Gateway')
        deviation_scores = payload.get('Deviation_scores')
        real_labels = payload.get('Real_labels')
        attack_types = payload.get('Attack_types')
        alertDB = payload.get('alertDB')
        alertDB = self.decodeAlertDB(alertDB)

        self.correlateTime(stime, etime, gateway, deviation_scores, real_labels, attack_types, alertDB)

    def start(self):
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_message = self.on_message
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_publish = self.on_publish
        
        self.mqtt_client.connect(self.broker, self.port)
        try:
            thread = Thread(target=self.mqtt_client.loop_forever)
            thread.start()
            
        except KeyboardInterrupt:
            print("Interrupted")
            p = Path('Detections')
            q = p / 'Correlation' 
            if not q.exists():
                q.mkdir(parents=True)
            alertsFile = open(str(q) + "/NumberOfAlertsCorrelationTime.csv", "a")
            alertsFile.write("NumberOfAlerts\n" + self.alertCounter)
            alertsFile.close()
            self.mqtt_client.disconnect()
