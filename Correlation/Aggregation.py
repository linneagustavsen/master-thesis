from datetime import timedelta,datetime, timezone
from pathlib import Path
import pprint
import pandas as pd
import paho.mqtt.client as mqtt
from time import sleep
from random import randrange
from threading import Thread, Timer
import json
import networkx as nx

from HelperFunctions.AttackIntervals import inAttackInterval

#Parameters for the MQTT connection
MQTT_BROKER = 'localhost'
MQTT_PORT = 1883
MQTT_USER = 'aggregation'
MQTT_PASSWORD = 'aggregationPass'
MQTT_TOPIC_INPUT = 'detections/modules/#'
MQTT_TOPIC_OUTPUT_TIME = 'detections/aggregation/time'
MQTT_TOPIC_OUTPUT_IPS = 'detections/aggregation/ips'
MQTT_TOPIC_OUTPUT_ATTACK_TYPE = 'detections/aggregation/attackType'
MQTT_TOPIC_OUTPUT_Distribution = 'detections/aggregation/distribution'

class Aggregation:
    """
        The class is initialized with data fields and database dictionaries.
    """
    def __init__(self, broker, port, inputTopic, outputTopicRanking, outputTopicIPs, outputTopicAttackTypes, outputDist, graph, attackDate):
        self.port = port
        self.broker = broker
        self.input = inputTopic
        self.outputRanking = outputTopicRanking
        self.outputIPs = outputTopicIPs
        self.outputAttackTypes = outputTopicAttackTypes
        self.outputDist = outputDist
        self.graph = graph
        self.alertCounter = 0
        self.lastAlertCounter = 0
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
        self.alertDB = {}
        for node in self.graph.G:
            self.alertDB[node] = {}

        self.alertDBDistribution = {}
        for node in self.graph.G:
            self.alertDBDistribution[node] = {}

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

    def addAlertToGraph(self, gateway, interval, alert, alertDB):
        if alertDB == 0:
            newAlert = dict(alert)
            newAlert.pop("Packet_size_distribution", None)
            if interval in self.getTimes(gateway, self.alertDB):
                self.alertDB[gateway][interval].append(newAlert)
            else:
                self.alertDB[gateway][interval] = [newAlert]
        elif alertDB == 1:
            if interval in self.getTimes(gateway, self.alertDBDistribution):
                self.alertDBDistribution[gateway][interval].append(alert)
            else:
                self.alertDBDistribution[gateway][interval] = [alert]

    def removeTimestampFromGraph(self, gateway, interval, alertDB):
        if alertDB == 0:
            self.alertDB[gateway].pop(interval, None)
        elif alertDB == 1:
            self.alertDBDistribution[gateway].pop(interval, None)

    def getTimes(self, gateway, alertDB):
        return alertDB[gateway]

    def getAlerts(self, gateway, interval, alertDB):
        return alertDB[gateway][interval]

    def encodeAlertsDB(self, alertDB):
        newAlertDB = {}
        for gateway in alertDB:
            newAlertDB[gateway] = {}
            times = list(alertDB[gateway].keys())
            for time in times:
                start = time.left.strftime("%Y-%m-%dT%H:%M:%SZ")
                end = time.right.strftime("%Y-%m-%dT%H:%M:%SZ")
                newAlertDB[gateway][str(str(start)+ "," + str(end))] = alertDB[gateway][time]
        return newAlertDB
    
    def aggregateTime(self):
        if self.alertCounter == self.lastAlertCounter or self.alertCounter == 0:
            thread2 = Timer(60, self.aggregateTime)
            thread2.start()
            return
        stime = self.startTime
        etime = self.startTime + timedelta(seconds=60)
        interval = pd.Interval(stime, etime, closed='both')
        
        overlappingAlerts = 0
        deviation_scores = []
        real_labels = []
        attack_types = {}
        gateways = []
        alreadyAlertedGateways = []
        
        gatewayNodes = list(self.graph.G.nodes)
        numberOfGateways = len(gatewayNodes)
        for i in range(numberOfGateways):
            gateway = gatewayNodes[i]
            if gateway in alreadyAlertedGateways:
                continue
            removeTimesGateway = []
            overlapTimes = []
            timesGateway = list(self.getTimes(gateway, self.alertDB).keys())
            overlap = False
            for timeGateway in timesGateway:
                #Remove old alerts from the data structure
                if timeGateway.left < stime - timedelta(minutes = 15):
                    removeTimesGateway.append(timeGateway)
                    continue
                if interval.overlaps(timeGateway):
                    overlap = True
                    overlapTimes.append(timeGateway)
                            
            for time in removeTimesGateway:
                removeAlerts = list(self.getAlerts(gateway, time, self.alertDB))
                remove_labels = []
                for alert in removeAlerts:
                    remove_labels.append(alert["Real_label"])
                self.findPerformance(remove_labels, time.left, time.right, 0)

                self.removeTimestampFromGraph(gateway, time, 0)

            if len(self.getTimes(gateway, self.alertDB).keys()) == 0 or not overlap:
                continue
            timeExists = False
            removeTimesOtherGatewayBecauseOfAlert = {}
            for j in range(i +1, numberOfGateways):
                otherGateway = gatewayNodes[j]
                if otherGateway == gateway:
                    continue
    
                if nx.shortest_path_length(self.graph.G, gateway, otherGateway) > 2:
                    continue

                if otherGateway in alreadyAlertedGateways:
                    continue
                
                removeTimesOtherGateway = []
                removeTimesOtherGatewayBecauseOfAlert[gateway] = []
                timesOtherGateway = list(self.getTimes(otherGateway, self.alertDB).keys())
                for timeOtherGateway in timesOtherGateway:
                    #Remove old alerts from the data structure
                    if timeOtherGateway.left < stime - timedelta(minutes = 15):
                        removeTimesOtherGateway.append(timeOtherGateway)
                        continue
                
                    #Go through all the time intervals for this gateway and see if this new alert overlaps with any other previous time intervals
                    if interval.overlaps(timeOtherGateway):
                        timeExists = True
                        alertsOtherGateway = list(self.getAlerts(otherGateway, timeOtherGateway, self.alertDB))
                        gateways.append(otherGateway)
                        removeTimesOtherGatewayBecauseOfAlert[gateway].append(timeOtherGateway)
                        #overlappingAlerts +=len(alertsOtherGateway)

                        for alert in alertsOtherGateway:
                            if not alert["Deviation_score"] == None:
                                deviation_scores.append(alert["Deviation_score"])
                            real_labels.append(alert["Real_label"])
                            if not alert["Attack_type"] == None:
                                if alert["Attack_type"] in attack_types:
                                    attack_types[alert["Attack_type"]] += alert["Weight"]
                                else:
                                    attack_types[alert["Attack_type"]] = alert["Weight"]
                            overlappingAlerts += alert["Weight"]
                
                for time in removeTimesOtherGateway:
                    removeAlerts = list(self.getAlerts(otherGateway, time, self.alertDB))
                    remove_labels = []
                    for alert in removeAlerts:
                        remove_labels.append(alert["Real_label"])
                    self.findPerformance(remove_labels, time.left, time.right, 0)
                    self.removeTimestampFromGraph(otherGateway, time, 0)
            removeTimesGatewayBecauseOfAlert = []
            if timeExists and gateway not in alreadyAlertedGateways:
                gateways.append(gateway)
                for timeGateway in overlapTimes:
                    alertsGateway = list(self.getAlerts(gateway, timeGateway, self.alertDB))
                    #overlappingAlerts += len(alertsGateway)
                    alreadyAlertedGateways.append(gateway)
                    removeTimesGatewayBecauseOfAlert.append(timeGateway)
                    for alert in alertsGateway:
                        if not alert["Deviation_score"] == None:
                            deviation_scores.append(alert["Deviation_score"])
                        real_labels.append(alert["Real_label"])
                        if not alert["Attack_type"] == None:
                            if alert["Attack_type"] in attack_types:
                                attack_types[alert["Attack_type"]] += alert["Weight"]
                            else:
                                attack_types[alert["Attack_type"]] = alert["Weight"]
                        overlappingAlerts += alert["Weight"]

            if not overlappingAlerts == 0:
                print("\nOverlappingAlerts for gateway",gateway, "and gateways",list(set(gateways)), "at time", interval)
                print(overlappingAlerts)
                            
            if overlappingAlerts > 0.03 and timeExists and len(gateways) > 2:
                for gateway in gateways:
                    alreadyAlertedGateways.append(gateway)
                message = {'sTime': stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        'eTime': etime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        'Gateways': list(set(gateways)),
                        'Deviation_scores': deviation_scores,
                        'Real_labels': self.countElements(real_labels),
                        'Attack_types':  attack_types,
                        'Weight': overlappingAlerts}

                self.mqtt_client.publish(self.outputRanking, json.dumps(message))
                print("Aggregation published to topic", self.outputRanking)
                self.findPerformance(real_labels, stime, etime, 1)

                for otherGateway in removeTimesOtherGatewayBecauseOfAlert:
                    timesOtherGateway = list(self.getTimes(otherGateway, self.alertDB).keys())
                    for time in timesOtherGateway:
                        self.removeTimestampFromGraph(otherGateway, time, 0)
                        counter = 0
                        for attackInterval in self.attackIntervals:
                            if attackInterval.overlaps(time) and 1 in real_labels:
                                self.detectedAttacks[counter] = True
                            counter += 1
                for time in removeTimesGatewayBecauseOfAlert:
                    self.removeTimestampFromGraph(gateway, time, 0)
                    counter = 0
                    for attackInterval in self.attackIntervals:
                        if attackInterval.overlaps(time) and 1 in real_labels:
                            self.detectedAttacks[counter] = True
                        counter += 1

                overlappingAlerts = 0
                deviation_scores = []
                real_labels = []
                attack_types = {}
                gateways = []


        self.lastAlertCounter = self.alertCounter
        self.startTime += timedelta(seconds=60)
        thread2 = Timer(60, self.aggregateTime)
        thread2.start()

    def aggregateTimeDistribution(self, stime, etime, gateway, distribution, payload):
        stime = pd.Timestamp(stime)
        etime = pd.Timestamp(etime)
        fuzzyStartTime = stime - timedelta(minutes = 1)
        interval = pd.Interval(fuzzyStartTime, etime, closed='both')
        overlappingAlerts = 0
        deviation_scores = []
        real_labels = []
        attack_types = {}
        distributions = []
        removeTimes = []
        removeTimesOtherGatewayBecauseOfAlert = []

        self.addAlertToGraph(gateway, interval, payload, 1)
        times = list(self.getTimes(gateway, self.alertDBDistribution).keys())
        for time in times:
            #Remove old alerts from the data structure
            if time.left < stime - timedelta(minutes = 15):
                removeTimes.append(time)
                continue
            
            #Go through all the time intervals for this gateway and see if this new alert overlaps with any other previous time intervals
            if interval.overlaps(time):
                alerts = list(self.getAlerts(gateway, time, self.alertDBDistribution))
                #overlappingAlerts += len(alerts)
                removeTimesOtherGatewayBecauseOfAlert.append(time)

                for alert in alerts:
                    if not alert["Deviation_score"] == None:
                        deviation_scores.append(alert["Deviation_score"])
                    real_labels.append(alert["Real_label"])
                    if not alert["Attack_type"] == None:
                        if alert["Attack_type"] in attack_types:
                            attack_types[alert["Attack_type"]] += alert["Weight"]
                        else:
                            attack_types[alert["Attack_type"]] = alert["Weight"]
                    distributions.append(alert["Packet_size_distribution"])
                    overlappingAlerts += alert["Weight"]

        for time in removeTimes:
            self.removeTimestampFromGraph(gateway, time, 1)

        print("\nOverlappingAlerts for gateway", gateway)
        print(overlappingAlerts)
        if overlappingAlerts > 0:

            message = {'sTime': stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    'eTime': etime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    'Gateway': gateway,
                    'Deviation_scores': deviation_scores,
                    'Real_labels': real_labels,
                    'Attack_types': attack_types,
                    'Packet_size_distributions': distributions,
                    'alertDB': self.encodeAlertsDB(self.alertDBDistribution),
                    'Weight': overlappingAlerts}

            self.mqtt_client.publish(self.outputDist, json.dumps(message))
            print("Aggregation published to topic", self.outputDist)
        else:
            print("No overlapping alerts for distribution for time interval", interval)
    """
        The MQTT commands are listened to and appropriate actions are taken for each.
    """
    def on_connect(self, client, userdata, flags, rc):
        print("Connected with result code "+str(rc))
        self.mqtt_client.subscribe(self.input)

    def on_message(self, client, userdata, msg):
        #print('Incoming message to topic {}'.format(msg.topic))
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
        except Exception as err:
            print('Message sent from topic {} had no valid JSON. Message ignored. {}'.format(msg.topic, err))
            return
        if self.alertCounter == 0:
            self.startTime = pd.Timestamp(payload.get('sTime')).replace(second=0)
        if payload.get('sTime') == "WRITE":
            p = Path('Detections' + self.fileString)
            q = p / 'Correlation' 
            if not q.exists():
                q.mkdir(parents=True)
            alertsFile = open(str(q) + "/NumberOfAlertsAggregation.csv", "a")
            alertsFile.write("NumberOfAlertsIn,TPin,FPin,TPout,FPout,TPoutCombined,FPoutCombined\n")
            alertsFile.write(str(self.alertCounter) +"," + str(self.truePositivesIn) + ","+ str(self.falsePositivesIn)+"," + str(self.truePositivesOut) + ","+ str(self.falsePositivesOut) + "," +str(self.combinedTruePositivesOut) + "," + str(self.combinedFalsePositivesOut))
            alertsFile.close()

            alertsFile = open(str(q) + "/DetectionAttackTypesAggregation.csv", "a")
            alertsFile.write(",".join(attackType for attackType in self.attacks))
            alertsFile.write("\n")
            alertsFile.write(",".join(str(i) for i in self.detectedAttacks))
            alertsFile.close()

            attackScores = open(str(q) + "/ScoresAttackTypes.Aggregation.json", "w")
            json.dump(self.attackDict,attackScores)
            attackScores.close()
        else:
            self.alertCounter += 1
            stime = payload.get('sTime')
            etime = payload.get('eTime')
            gateway = payload.get('Gateway')
            srcIP = payload.get('srcIP')
            dstIP = payload.get('dstIP')
            packetSizeDistribution = payload.get('Packet_size_distribution')

            #self.aggregateTime(stime, etime, gateway, payload)

            if payload.get('Attack_type') != '':
                self.mqtt_client.publish(self.outputAttackTypes, json.dumps(payload))
                #print("Aggregation published to topic", self.outputAttackTypes)
            if srcIP != None or dstIP != None:
                self.mqtt_client.publish(self.outputIPs, json.dumps(payload))
                #print("Aggregation published to topic", self.outputIPs)
            if packetSizeDistribution != None:
                self.aggregateTimeDistribution(stime, etime, gateway, packetSizeDistribution, payload)
            if int(payload.get('Real_label')) == 0:
                self.falsePositivesIn += 1
            elif int(payload.get('Real_label')) == 1:
                self.truePositivesIn += 1
            
            stime = pd.Timestamp(stime)- timedelta(seconds = 2)
            etime = pd.Timestamp(etime)
            interval = pd.Interval(stime, etime, closed='both')
            self.addAlertToGraph(gateway, interval, payload, 0)


    def start(self):
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_message = self.on_message
        self.mqtt_client.on_connect = self.on_connect

        self.mqtt_client.connect(self.broker, self.port)
        try:
            self.mqtt_client.loop_start()
            thread2 = Timer(60, self.aggregateTime)
            thread2.start()
            
        except:
            print("Interrupted")
            
            self.mqtt_client.disconnect()
