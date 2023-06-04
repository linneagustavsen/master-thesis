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
MQTT_TOPIC_INPUT = 'detections/aggregation/attackType'
MQTT_TOPIC_OUTPUT = 'detections/correlation'

"""
    This class is for correlating alerts
"""
class Correlation_Attack_types:
    def __init__(self, broker, port, inputTopic, outputTopic, attackDate):
        self.port = port
        self.broker = broker
        self.input = inputTopic
        self.output = outputTopic
        self.alertsAttack ={}
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
  
        if 1 not in counter:
            self.falsePositivesOut += 1
        elif 0 not in counter:
            self.truePositivesOut += 1
        else:
            if counter[0] > counter[1]:
                self.falsePositivesOut += 1
            elif counter[0] < counter[1]:
                self.truePositivesOut += 1
        return counter


    def addAlert(self, attackType, interval, alert):
        if attackType in self.alertsAttack:
            if interval in self.getTimes(attackType):
                self.alertsAttack[attackType][interval].append(alert)
            else:
                self.alertsAttack[attackType] = {interval:[alert]}
        else:
                self.alertsAttack[attackType] = {interval:[alert]}

    def getTimes(self, attackType):
        return self.alertsAttack[attackType]
    
    def getAlerts(self, attackType, interval):
        return self.alertsAttack[attackType][interval]
    
    def removeTimestampFromAttackType(self, attackType, interval):
        del self.alertsAttack[attackType][interval]

    def correlateAttackTypes(self, stime, etime, attackType, payload):
        stime = pd.Timestamp(stime)
        etime = pd.Timestamp(etime)
        fuzzyStartTime = stime - timedelta(minutes = 15)
        interval = pd.Interval(fuzzyStartTime, etime, closed='both')
        

        self.addAlert(attackType, interval, payload)

        overlappingAlerts = 0
        gateways = [payload.get('Gateway')]
        deviation_scores = []
        real_labels = []
        removeTimes = []

        for time in self.getTimes(attackType):
            if time.left < stime - timedelta(minutes = 15):
                removeTimes.append(time)
                continue

            if interval.overlaps(time):
                alerts = self.getAlerts(attackType, time)
                overlappingAlerts += len(alerts)

                for alert in alerts:
                    gateways.append(alert['Gateway'])
                    if not alert["Deviation_score"] == None:
                        deviation_scores.append(alert["Deviation_score"])
                    real_labels.append(alert["Real_label"])

        for time in removeTimes:
            self.removeTimestampFromAttackType(attackType, time)

        print("\nOverlappingAlerts on attack type", attackType)
        print(overlappingAlerts)
        if overlappingAlerts > 10:

            message = { 'sTime': stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        'eTime': etime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        'Gateways': list(set(gateways)),
                        'Deviation_scores': deviation_scores,
                        'Real_labels': self.countElements(real_labels),
                        'Attack_types': {attackType: overlappingAlerts}
                        }
            
            self.mqtt_client.publish(self.output, json.dumps(message))
            print("\nPublished message to topic", self.output)
        else:
            print("No overlapping alerts for time interval", interval)

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
            alertsFile = open(str(q) + "/NumberOfAlertsCorrelationAttackType.csv", "a")
            alertsFile.write("NumberOfAlertsIn,TPin,FPin,TPout,FPout\n" + str(self.alertCounter) +"," + str(self.truePositivesIn) + ","+ str(self.falsePositivesIn)+"," + str(self.truePositivesOut) + ","+ str(self.falsePositivesOut))
            alertsFile.close()
        else:
            self.alertCounter += 1
            stime = payload.get('sTime')
            etime = payload.get('eTime')
            attackType = payload.get('Attack_type')

            self.correlateAttackTypes(stime, etime, attackType, payload)
            if int(payload.get('Real_label')) == 0:
                self.falsePositivesIn += 1
            elif int(payload.get('Real_label')) == 1:
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
