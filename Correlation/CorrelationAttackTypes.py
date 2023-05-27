from pathlib import Path
import pandas as pd
import paho.mqtt.client as mqtt
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
    def __init__(self, broker, port, inputTopic, outputTopic):
        self.port = port
        self.broker = broker
        self.input = inputTopic
        self.output = outputTopic
        self.alertsAttack ={}
        self.alertCounter = 0

    def countElements(self, listOfElements):
        counter = {}
        for element in listOfElements:
            if element in counter:
                counter[element] += 1
            else:
                counter[element] = 1
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
        print("\n removeTimestampFromAttackType")
        print(self.alertsAttack)
        del self.alertsAttack[attackType][interval]

    def correlateAttackTypes(self, stime, etime, attackType, payload):
        stime = pd.Timestamp(stime)
        etime = pd.Timestamp(etime)
        fuzzyStartTime = stime - timedelta(minutes = 15)
        interval = pd.Interval(fuzzyStartTime, etime, closed='both')

        if attackType in self.alertsAttack:
            exists = False
            existingTimes = []
            overlappingAlerts = 1
            gateways = [payload.get('Gateway')]
            deviation_scores = []
            real_labels = []
            removeTimes = []

            for time in self.getTimes(attackType):
                if time.left < stime - timedelta(minutes = 15):
                    removeTimes.append(time)
                    continue

                if interval.overlaps(time):
                    exists = True
                    existingTimes.append(time)
                    alerts = self.getAlerts(attackType, time)
                    overlappingAlerts += len(alerts)

                    for alert in alerts:
                        gateways.append(alert['Gateway'])
                        deviation_scores.append(alert["Deviation_score"])
                        real_labels.append(alert["Real_label"])
    
            for time in removeTimes:
                self.removeTimestampFromAttackType(attackType, time)
                if time in existingTimes:
                    existingTimes.remove(time)
            if exists:
                for existingTime in existingTimes:
                    self.addAlert(attackType, existingTime, payload)

                print("\nOverlappingAlerts")
                print(overlappingAlerts)
                print("\n")
                if overlappingAlerts > 3:

                    message = { 'sTime': stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                'eTime': etime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                'Gateways': list(set(gateways)),
                                'Deviation_scores': deviation_scores,
                                'Real_labels': self.countElements(real_labels),
                                'Attack_types': {attackType: overlappingAlerts}
                                }
                    
                    self.mqtt_client.publish(self.output, json.dumps(message))
                    print("\nPublished message to topic", self.output)
                    print(message)
                    print("\n")
            else:
                self.addAlert(attackType, interval, payload)
                print("No overlapping alerts for time interval", interval)
        else:
            self.addAlert(attackType, interval, payload)
            print("No attack type of type", attackType)

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
        attackType = payload.get('Attack_type')

        self.correlateAttackTypes(stime, etime, attackType, payload)

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
            alertsFile = open(str(q) + "/NumberOfAlertsCorrelationAttackType.csv", "a")
            alertsFile.write("NumberOfAlerts\n" + self.alertCounter)
            alertsFile.close()
            self.mqtt_client.disconnect()
