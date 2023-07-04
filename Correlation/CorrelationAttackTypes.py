from pathlib import Path
import pandas as pd
import paho.mqtt.client as mqtt
from time import sleep
from random import randrange
from threading import Thread, Timer
import json
from datetime import timedelta,datetime, timezone

from HelperFunctions.AttackIntervals import inAttackInterval

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
    def __init__(self, broker, port, inputTopic, outputTopic, threshold, attackDate):
        self.port = port
        self.broker = broker
        self.input = inputTopic
        self.output = outputTopic
        self.alertsAttack ={}
        self.alertCounter = 0
        self.lastAlertCounter = 0
        self.truePositivesIn = 0
        self.falsePositivesIn = 0
        self.truePositivesOut = 0
        self.falsePositivesOut = 0
        self.combinedTruePositivesOut = 0
        self.combinedFalsePositivesOut = 0
        self.threshold = int(threshold)

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


    def addAlert(self, attackType, interval, alert):
        if attackType in self.alertsAttack:
            if interval in self.getTimes(attackType):
                self.alertsAttack[attackType][interval].append(alert)
            else:
                self.alertsAttack[attackType][interval] = [alert]
        else:
            self.alertsAttack[attackType] = {interval:[alert]}

    def getTimes(self, attackType):
        return self.alertsAttack[attackType]
    
    def getAlerts(self, attackType, interval):
        return self.alertsAttack[attackType][interval]
    
    def removeTimestampFromAttackType(self, attackType, interval):
        del self.alertsAttack[attackType][interval]

    def correlateAttackTypes(self):
        if self.alertCounter == self.lastAlertCounter or self.alertCounter == 0:
            thread2 = Timer(60, self.correlateAttackTypes)
            thread2.start()
            return
        stime = self.startTime
        etime = self.startTime + timedelta(seconds=60)
        interval = pd.Interval(stime, etime, closed='both')
        attackTypesDb = dict(self.alertsAttack)
        for attackType in attackTypesDb:
            overlappingAlerts = 0
            gateways = []
            deviation_scores = []
            real_labels = []
            removeTimes = []
            removeTimesOtherGatewayBecauseOfAlert = []
	    
            times = list(self.getTimes(attackType).keys())
            for time in times:
                if time.left < stime - timedelta(minutes = 15):
                    removeTimes.append(time)
                    continue

                if interval.overlaps(time):
                    alerts = list(self.getAlerts(attackType, time))
                    removeTimesOtherGatewayBecauseOfAlert.append(time)
                    #overlappingAlerts += len(alerts)

                    for alert in alerts:
                        gateways.append(alert['Gateway'])
                        if not alert["Deviation_score"] == None:
                            deviation_scores.append(alert["Deviation_score"])
                        real_labels.append(alert["Real_label"])
                        overlappingAlerts += alert["Weight"]

            for time in removeTimes:
                removeAlerts = list(self.getAlerts(attackType, time))
                remove_labels = []
                for alert in removeAlerts:
                    remove_labels.append(alert["Real_label"])
                self.findPerformance( remove_labels, time.left, time.right, 0)

                self.removeTimestampFromAttackType(attackType, time)

            print("\nOverlappingAlerts on attack type", attackType)
            print(overlappingAlerts)
            if overlappingAlerts > 0.02 and attackType == "SYN Flood":

                message = { 'sTime': stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                            'eTime': etime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                            'Gateways': list(set(gateways)),
                            'Deviation_scores': deviation_scores,
                            'Real_labels': self.countElements(real_labels),
                            'Attack_types': {attackType: overlappingAlerts},
                            'Weight': overlappingAlerts
                            }
                
                self.mqtt_client.publish(self.output, json.dumps(message))
                print("\nPublished message to topic", self.output)
                self.findPerformance( real_labels, stime, etime, 1)
                for time in removeTimesOtherGatewayBecauseOfAlert:
                    self.removeTimestampFromAttackType(attackType, time)
                    counter = 0
                    for attackInterval in self.attackIntervals:
                        if attackInterval.overlaps(time) and 1 in real_labels:
                            self.detectedAttacks[counter] = True
                        counter += 1

            elif overlappingAlerts >0.003 and attackType != "SYN Flood":
                message = { 'sTime': stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                            'eTime': etime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                            'Gateways': list(set(gateways)),
                            'Deviation_scores': deviation_scores,
                            'Real_labels': self.countElements(real_labels),
                            'Attack_types': {attackType: overlappingAlerts},
                            'Weight': overlappingAlerts
                            }
                
                self.mqtt_client.publish(self.output, json.dumps(message))
                print("\nPublished message to topic", self.output)
                self.findPerformance( real_labels, stime, etime, 1)
                for time in removeTimesOtherGatewayBecauseOfAlert:
                    self.removeTimestampFromAttackType(attackType, time)
                    counter = 0
                    for attackInterval in self.attackIntervals:
                        if attackInterval.overlaps(time) and 1 in real_labels:
                            self.detectedAttacks[counter] = True
                        counter += 1
        self.lastAlertCounter = self.alertCounter
        self.startTime += timedelta(seconds=60)
        thread2 = Timer(60, self.correlateAttackTypes)
        thread2.start()
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
        if self.alertCounter == 0:
            self.startTime = pd.Timestamp(payload.get('sTime'))
        if payload.get('sTime') == "WRITE":
            p = Path('Detections' + self.fileString)
            q = p / 'Correlation' 
            if not q.exists():
                q.mkdir(parents=True)
            alertsFile = open(str(q) + "/NumberOfAlertsCorrelationAttackType.csv", "a")
            alertsFile.write("NumberOfAlertsIn,TPin,FPin,TPout,FPout,TPoutCombined,FPoutCombined\n")
            alertsFile.write(str(self.alertCounter) +"," + str(self.truePositivesIn) + ","+ str(self.falsePositivesIn)+"," + str(self.truePositivesOut) + ","+ str(self.falsePositivesOut) + "," +str(self.combinedTruePositivesOut) + "," + str(self.combinedFalsePositivesOut))
            alertsFile.close()

            alertsFile = open(str(q) + "/DetectionAttackTypesCorrelationAttackType.csv", "a")
            alertsFile.write(",".join(attackType for attackType in self.attacks))
            alertsFile.write("\n")
            alertsFile.write(",".join(str(i) for i in self.detectedAttacks))
            alertsFile.close()

            attackScores = open(str(q) + "/ScoresAttackTypes.CorrelationAttackType.json", "w")
            json.dump(self.attackDict,attackScores)
            attackScores.close()
        else:
            self.alertCounter += 1
            stime = payload.get('sTime')
            etime = payload.get('eTime')
            attackType = payload.get('Attack_type')

            #self.correlateAttackTypes(stime, etime, attackType, payload)
            if int(payload.get('Real_label')) == 0:
                self.falsePositivesIn += 1
            elif int(payload.get('Real_label')) == 1:
                self.truePositivesIn += 1
            stime = pd.Timestamp(stime)
            etime = pd.Timestamp(etime)
            interval = pd.Interval(stime, etime, closed='both')
            self.addAlert(attackType, interval, payload)

    def start(self):
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_message = self.on_message
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_publish = self.on_publish
        
        self.mqtt_client.connect(self.broker, self.port)
        try:
            self.mqtt_client.loop_start()
            thread2 = Timer(60, self.correlateAttackTypes)
            thread2.start()
            
        except:
            print("Interrupted")
            
            self.mqtt_client.disconnect()
