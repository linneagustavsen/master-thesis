from datetime import timedelta
from pathlib import Path
import pandas as pd
import paho.mqtt.client as mqtt
from threading import Thread
import json

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
    def __init__(self, broker, port, inputTopic, outputTopicTime, outputTopicIPs, outputTopicAttackTypes, outputDist, graph, attackDate):
        self.port = port
        self.broker = broker
        self.input = inputTopic
        self.outputTime = outputTopicTime
        self.outputIPs = outputTopicIPs
        self.outputAttackTypes = outputTopicAttackTypes
        self.outputDist = outputDist
        self.graph = graph
        self.alertCounter = 0

        if attackDate == "08.03.23":
            self.fileString = "0803"
        elif attackDate == "17.03.23":
            self.fileString = "1703"
        elif attackDate == "24.03.23":
            self.fileString = "2403"

        self.alertDB = {}
        for node in self.graph.G:
            self.alertDB[node] = {}

        self.alertDBDistribution = {}
        for node in self.graph.G:
            self.alertDBDistribution[node] = {}

    def countElements(self, listOfElements):
        counter = {}
        for element in listOfElements:
            if element in counter:
                counter[element] += 1
            else:
                counter[element] = 1
        return counter    

    def addAlertToGraph(self, gateway, interval, alert, alertDB):
        if alertDB == 0:
            if interval in self.getTimes(gateway, self.alertDB):
                self.alertDB[gateway][interval].append(alert)
            else:
                self.alertDB[gateway][interval] = [alert]
        elif alertDB == 1:
            if interval in self.getTimes(gateway, self.alertDBDistribution):
                self.alertDBDistribution[gateway][interval].append(alert)
            else:
                self.alertDBDistribution[gateway][interval] = [alert]

    def removeTimestampFromGraph(self, gateway, interval, alertDB):
        if alertDB == 0:
            del self.alertDB[gateway][interval]
        elif alertDB == 1:
            del self.alertDBDistribution[gateway][interval]

    def getTimes(self, gateway, alertDB):
        return alertDB[gateway]

    def getAlerts(self, gateway, interval, alertDB):
        return alertDB[gateway][interval]

    def encodeAlertsDB(self, alertDB):
        newAlertDB = {}
        for gateway in alertDB:
            newAlertDB[gateway] = {}
            for time in alertDB[gateway]:
                start = time.left.strftime("%Y-%m-%dT%H:%M:%SZ")
                end = time.right.strftime("%Y-%m-%dT%H:%M:%SZ")
                newAlertDB[gateway][str(str(start)+ "," + str(end))] = alertDB[gateway][time]
        return newAlertDB
    
    def aggregateTime(self, stime, etime, gateway, payload):
        stime = pd.Timestamp(stime)
        etime = pd.Timestamp(etime)
        fuzzyStartTime = stime - timedelta(seconds = 2)
        interval = pd.Interval(fuzzyStartTime, etime, closed='both')
        exists = False
        existingTimes = []
        overlappingAlerts = 1
        deviation_scores = []
        real_labels = []
        attack_types = []
        removeTimes = []

        for time in self.getTimes(gateway, self.alertDB):
            #Remove old alerts from the data structure
            if time.left < stime - timedelta(minutes = 15):
                removeTimes.append(time)
                continue
            
            #Go through all the time intervals for this gateway and see if this new alert overlaps with any other previous time intervals
            if interval.overlaps(time):
                exists = True
                existingTimes.append(time)
                alerts = self.getAlerts(gateway, time, self.alertDB)
                overlappingAlerts += len(alerts)

                for alert in alerts:
                    deviation_scores.append(alert["Deviation_score"])
                    real_labels.append(alert["Real_label"])
                    attack_types.append(alert["Attack_type"])
        
        for time in removeTimes:
            self.removeTimestampFromGraph(gateway, time, 0)

        if exists:
            for existingTime in existingTimes:
                self.addAlertToGraph(gateway, existingTime, payload, 0)

            print("\nOverlappingAlerts")
            print(overlappingAlerts)
            print("\n")
            if overlappingAlerts > 3:
                
                message = {'sTime': stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        'eTime': etime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        'Gateway': gateway,
                        'Deviation_scores': deviation_scores,
                        'Real_labels': real_labels,
                        'Attack_types': attack_types,
                        'alertDB': self.encodeAlertsDB(self.alertDB)}
    
                self.mqtt_client.publish(self.outputTime, json.dumps(message))
                print("Aggregation published to topic", self.outputTime)
        else:
            self.addAlertToGraph(gateway, interval, payload, 0)
            print("No overlapping alerts for time interval", interval)

    def aggregateTimeDistribution(self, stime, etime, gateway, distribution, payload):
        stime = pd.Timestamp(stime)
        etime = pd.Timestamp(etime)
        fuzzyStartTime = stime - timedelta(seconds = 2)
        interval = pd.Interval(fuzzyStartTime, etime, closed='both')
        exists = False
        existingTimes = []
        overlappingAlerts = 1
        deviation_scores = []
        real_labels = []
        attack_types = []
        distributions = [distribution]
        removeTimes = []

        for time in self.getTimes(gateway, self.alertDBDistribution):
            #Remove old alerts from the data structure
            if time.left < stime - timedelta(minutes = 15):
                removeTimes.append(time)
                continue
            
            #Go through all the time intervals for this gateway and see if this new alert overlaps with any other previous time intervals
            if interval.overlaps(time):
                exists = True
                existingTimes.append(time)
                alerts = self.getAlerts(gateway, time, self.alertDBDistribution)
                overlappingAlerts += len(alerts)

                for alert in alerts:
                    deviation_scores.append(alert["Deviation_score"])
                    real_labels.append(alert["Real_label"])
                    attack_types.append(alert["Attack_type"])
                    distributions.append(alert["Packet_size_distribution"])
        
        for time in removeTimes:
            self.removeTimestampFromGraph(gateway, time, 1)

        if exists:
            for existingTime in existingTimes:
                self.addAlertToGraph(gateway, existingTime, payload, 1)

            print("\nOverlappingAlerts")
            print(overlappingAlerts)
            print("\n")
            if overlappingAlerts > 3:
                
                message = {'sTime': stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        'eTime': etime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        'Gateway': gateway,
                        'Deviation_scores': deviation_scores,
                        'Real_labels': real_labels,
                        'Attack_types': attack_types,
                        'Packet_size_distributions': distributions,
                        'alertDB': self.encodeAlertsDB(self.alertDBDistribution)}
    
                self.mqtt_client.publish(self.outputDist, json.dumps(message))
                print("Aggregation published to topic", self.outputDist)
        else:
            self.addAlertToGraph(gateway, interval, payload, 1)
            print("No overlapping alerts for distribution for time interval", interval)
    """
        The MQTT commands are listened to and appropriate actions are taken for each.
    """
    def on_connect(self, client, userdata, flags, rc):
        print("Connected with result code "+str(rc))
        self.mqtt_client.subscribe(self.input)
        print("subscribed to", self.input)

    def on_message(self, client, userdata, msg):
        print('Incoming message to topic {}'.format(msg.topic))
        self.alertCounter += 1
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
            print(payload)
        except Exception as err:
            print('Message sent from topic {} had no valid JSON. Message ignored. {}'.format(msg.topic, err))
            return

        stime = payload.get('sTime')
        etime = payload.get('eTime')
        gateway = payload.get('Gateway')
        srcIP = payload.get('srcIP')
        dstIP = payload.get('dstIP')
        packetSizeDistribution = payload.get('Packet_size_distribution')

        self.aggregateTime(stime, etime, gateway, payload)
        
        if payload.get('Attack_type') != '':
            self.mqtt_client.publish(self.outputAttackTypes, json.dumps(payload))
            print("Aggregation published to topic", self.outputAttackTypes)
        if srcIP != None or dstIP != None:
            self.mqtt_client.publish(self.outputIPs, json.dumps(payload))
            print("Aggregation published to topic", self.outputIPs)
        if packetSizeDistribution != None:
            self.aggregateTimeDistribution(stime, etime, gateway, packetSizeDistribution, payload)

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
            p = Path('Detections' + self.fileString)
            q = p / 'Correlation' 
            if not q.exists():
                q.mkdir(parents=True)
            alertsFile = open(str(q) + "/NumberOfAlertsAggregation.csv", "a")
            alertsFile.write("NumberOfAlerts\n" + self.alertCounter)
            alertsFile.close()
            self.mqtt_client.disconnect()
