from pathlib import Path
import pandas as pd
from Correlation.NetworkGraph import NetworkGraph
import paho.mqtt.client as mqtt
from time import sleep
from random import randrange
import networkx as nx
from threading import Thread
import json
from datetime import datetime, timedelta, timezone
from HelperFunctions.AttackIntervals import inAttackInterval

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
        self.combinedTruePositivesOut = 0
        self.combinedFalsePositivesOut = 0

        self.attackIntervals = []
        self.detectedAttacks = []

        self.attackDate = attackDate
        
        if attackDate == "08.03.23":
            self.fileString = "0803"
            self.startTime = pd.Timestamp("2023-03-08T14:15:00Z")
            self.stopTime = pd.Timestamp("2023-03-08T16:00:00Z")
            strings = [["Mar 08 14:29:55", "Mar 08 14:34:56"], ["Mar 08 14:49:56", "Mar 08 15:02:57"],
           ["Mar 08 15:09:56", "Mar 08 15:17:02"], ["Mar 08 15:37:00", "Mar 08 15:52:02"]]
            self.attackDict = {"SYN Flood":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "SlowLoris": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "Ping Flood": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "R.U.D.Y":{"TP":0, "FP":0, "TN": 0, "FN": 0}}
            self.attacks = ["SYN Flood", "SlowLoris", "Ping Flood", "R.U.D.Y"]
        elif attackDate == "17.03.23":
            self.fileString = "1703"
            self.startTime = pd.Timestamp("2023-03-17T11:00:00Z")
            self.stopTime = pd.Timestamp("2023-03-17T13:00:00Z")
            strings = [
           ["Mar 17 11:00:01", "Mar 17 11:07:02"], ["Mar 17 11:37:02", "Mar 17 11:50:04"],
           ["Mar 17 11:57:02", "Mar 17 12:04:12"], ["Mar 17 12:44:10", "Mar 17 13:00:17"]]
            self.attackDict = {"SYN Flood":{"TP":0, "FP":0, "TN": 0, "FN": 0},
                       "SlowLoris": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "Ping Flood": {"TP":0, "FP":0, "TN": 0, "FN": 0}, 
                       "R.U.D.Y":{"TP":0, "FP":0, "TN": 0, "FN": 0}}
            self.attacks = ["SYN Flood", "SlowLoris", "Ping Flood", "R.U.D.Y"]
        elif attackDate == "24.03.23":
            self.fileString = "2403"
            self.startTime = pd.Timestamp("2023-03-24T14:00:00Z")
            self.stopTime = pd.Timestamp("2023-03-24T18:00:00Z")
            strings = [["Mar 24 14:00:01", "Mar 24 14:03:57"], ["Mar 24 14:13:29", "Mar 24 14:29:08"],
           ["Mar 24 14:46:30", "Mar 24 14:55:00"], ["Mar 24 14:59:50", "Mar 24 15:15:06"], 
           ["Mar 24 15:26:51", "Mar 24 15:39:22"], ["Mar 24 15:40:21", "Mar 24 15:47:50"], 
           ["Mar 24 16:07:29", "Mar 24 16:19:00"], ["Mar 24 16:22:29", "Mar 24 16:29:13"],
           ["Mar 24 16:29:53", "Mar 24 16:49:50"], ["Mar 24 16:53:22", "Mar 24 17:09:39"],
           ["Mar 24 17:25:15", "Mar 24 17:47:00"]]
            self.attackDict = {"UDP Flood":{"TP":0, "FP":0, "TN": 0, "FN": 0},
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
            self.attacks = ["UDP Flood", "SlowLoris", "Ping Flood", "Slow Read", "Blacknurse", "SYN Flood", "R.U.D.Y",
                "Xmas", "UDP Flood and SlowLoris", "Ping Flood and R.U.D.Y", "All types"]
        
        for string in strings:
            start = datetime.strptime(string[0], '%b %d %H:%M:%S').replace(year=2023).replace(tzinfo=timezone.utc)
            stop = datetime.strptime(string[1], '%b %d %H:%M:%S').replace(year=2023).replace(tzinfo=timezone.utc)

            intervalNow = pd.Interval(pd.Timestamp(start), pd.Timestamp(stop), closed="both")
            self.attackIntervals.append(intervalNow)
            self.detectedAttacks.append(False)
    def findPerformance(self, labels, sTime, eTime, didAlert):
        isInAttackTime, attackTypeDuringThisTime = inAttackInterval(sTime, eTime, self.attackDate)
    
        for label in labels:
            if label == 0 and isInAttackTime:
                if didAlert:
                    self.attackDict[attackTypeDuringThisTime]["FP"] += 1
                else:
                    self.attackDict[attackTypeDuringThisTime]["TN"] += 1
            elif label == 1 and isInAttackTime:
                if didAlert:
                    self.attackDict[attackTypeDuringThisTime]["TP"] += 1
                else:
                    self.attackDict[attackTypeDuringThisTime]["FN"] += 1
                    
    def countElements(self, listOfElements):
        counter = {}
        for element in listOfElements:
            if element in counter:
                counter[element] += 1
            else:
                counter[element] = 1

        if 0 or 1 in counter:
            if 1 not in counter:
                self.falsePositivesOut += counter[0]
                self.combinedFalsePositivesOut += 1
            elif 0 not in counter:
                self.truePositivesOut += counter[1]
                self.combinedTruePositivesOut += 1
            else:
                if counter[0] > counter[1]:
                    self.falsePositivesOut += counter[0]
                    self.combinedFalsePositivesOut += 1
                elif counter[0] < counter[1]:
                    self.truePositivesOut += counter[1]
                    self.combinedTruePositivesOut += 1
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

    def correlateDistribution(self, stime, etime, gateway, distributions, deviation_scores, real_labels, attack_types, weight, alertDB):
        timeExists = False
        gateways = [gateway]
        stime = pd.Timestamp(stime)
        etime = pd.Timestamp(etime)
        fuzzyStartTime = stime - timedelta(seconds = 1)
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
                                print("\nINFORMATION DISTANCE at time", str(time), "and gateway", gateway, "and", otherGateway)
                                print(informationDistance(10, distribution, alert["Packet_size_distribution"]))
                                if informationDistance(10, distribution, alert["Packet_size_distribution"]) < 10:
                                    timeExists = True
                                    gateways.append(otherGateway)
                                    deviation_scores.append(alert["Deviation_score"])
                                    real_labels.append(alert["Real_label"])
                                    if alert["Attack_type"] in attack_types:
                                        attack_types[alert["Attack_type"]] += alert["Weight"]
                                    else:
                                        attack_types[alert["Attack_type"]] = alert["Weight"]
                                    weight += alert["Weight"]

        if timeExists:
            message = {
                    "sTime": stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": etime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateways": list(set(gateways)),
                    "Deviation_scores": deviation_scores,
                    "Real_labels": self.countElements(real_labels),
                    "Attack_types": attack_types,
                    "Weight": weight
                    }
            
            print("\nPublished message to topic", self.output)
            self.mqtt_client.publish(self.output, json.dumps(message))
            self.findPerformance( real_labels, stime, etime, 1)
            counter = 0
            for attackInterval in self.attackIntervals:
                if attackInterval.overlaps(interval) and 1 in real_labels:
                    self.detectedAttacks[counter] = True
                counter += 1

    """
        The MQTT commands are listened to and appropriate actions are taken for each.
    """
    def on_connect(self, client, userdata, flags, rc):
        print("Connected with result code "+str(rc))
        self.mqtt_client.subscribe(self.input)

    def on_publish(self, client, userdata, result):
        print("Correlation published to topic", self.output)
    
    def on_message(self, client, userdata, msg):
        #print('Incoming message to topic {}'.format(msg.topic))
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
            alertsFile.write("NumberOfAlertsIn,TPin,FPin,TPout,FPout,TPoutCombined,FPoutCombined\n")
            alertsFile.write(str(self.alertCounter) +"," + str(self.truePositivesIn) + ","+ str(self.falsePositivesIn)+"," + str(self.truePositivesOut) + ","+ str(self.falsePositivesOut) + "," +str(self.combinedTruePositivesOut) + "," + str(self.combinedFalsePositivesOut))
            alertsFile.close()

            alertsFile = open(str(q) + "/DetectionAttackTypesCorrelationDistribution.csv", "a")
            alertsFile.write(",".join(attackType for attackType in self.attacks))
            alertsFile.write("\n")
            alertsFile.write(",".join(str(i) for i in self.detectedAttacks))
            alertsFile.close()

            attackScores = open(str(q) + "/ScoresAttackTypes.CorrelationDistribution.json", "w")
            json.dump(self.attackDict,attackScores)
            attackScores.close()

        else:
            self.alertCounter += 1
            stime = payload.get('sTime')
            etime = payload.get('eTime')
            gateway = payload.get('Gateway')
            deviation_scores = payload.get('Deviation_scores')
            real_labels = payload.get('Real_labels')
            attack_types = payload.get('Attack_types')
            weight = payload.get('Weight')
            alertDB = payload.get('alertDB')
            alertDB = self.decodeAlertDB(alertDB)
            distributions = payload.get('Packet_size_distributions')
            

            self.correlateDistribution(stime, etime, gateway, distributions, deviation_scores, real_labels, attack_types, weight, alertDB)
            for label in real_labels:
                if label == 1:
                    self.truePositivesIn += 1
                elif label == 0:
                    self.falsePositivesIn += 1

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
