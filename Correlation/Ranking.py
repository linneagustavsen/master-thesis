from datetime import datetime, timedelta, timezone
from pathlib import Path
import statistics
import numpy as np
import pandas as pd
from Correlation.NetworkGraph import NetworkGraph
import paho.mqtt.client as mqtt
from time import sleep
from random import randrange
from threading import Thread, Timer
import json

from HelperFunctions.AttackIntervals import inAttackInterval

#Parameters for the MQTT connection
MQTT_BROKER = 'localhost'
MQTT_PORT = 1883
MQTT_USER = 'aggregation'
MQTT_PASSWORD = 'aggregationPass'
MQTT_TOPIC_INPUT = 'detections/correlation/#'
MQTT_TOPIC_OUTPUT = 'detections/ranking'

class Ranking:
    """
        The class is initialized with data fields and database dictionaries.
    """
    def __init__(self, broker, port, inputTopic, outputTopic, graph, attackDate):
        self.port = port
        self.broker = broker
        self.input = inputTopic
        self.output = outputTopic
        self.graph = graph
        self.ranking = []
        self.rankingDeviationScore = []
        self.alertCounter = 0
        self.lastAlertCounter =0
        self.truePositivesIn = 0
        self.falsePositivesIn = 0
        self.truePositivesOut = 0
        self.falsePositivesOut = 0
        self.highRankingFalsePositives = 0
        self.highRankingTruePositives = 0
        self.highRankingTotal = 0
        self.highRankingFalsePositivesWeighted = 0
        self.highRankingTruePositivesWeighted = 0
        self.highRankingTotalWeighted = 0
        
        self.truePositivesOutDs = 0
        self.falsePositivesOutDs = 0
        self.highRankingFalsePositivesDs = 0
        self.highRankingTruePositivesDs = 0
        self.highRankingTotalDs = 0
        self.highRankingFalsePositivesWeightedDs = 0
        self.highRankingTruePositivesWeightedDs = 0
        self.highRankingTotalWeightedDs = 0 
        self.numberOfRankings = 0

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
            start = datetime.strptime(string[0], '%b %d %H:%M:%S').replace(year=2023)
            stop = datetime.strptime(string[1], '%b %d %H:%M:%S').replace(year=2023)

            intervalNow = pd.Interval(pd.Timestamp(start), pd.Timestamp(stop), closed="both")
            self.attackIntervals.append(intervalNow)
            self.detectedAttacks.append(False)

    def findPerformance(self, labels, sTime, eTime, didAlert):
        isInAttackTime, attackTypeDuringThisTime = inAttackInterval(sTime, eTime, self.attackDate)
    
        for label in labels:
            if label == '0' and isInAttackTime:
                if didAlert:
                    self.attackDict[attackTypeDuringThisTime]["FP"] += 1
                else:
                    self.attackDict[attackTypeDuringThisTime]["TN"] += 1
            elif label == '1' and isInAttackTime:
                if didAlert:
                    self.attackDict[attackTypeDuringThisTime]["TP"] += 1
                else:
                    self.attackDict[attackTypeDuringThisTime]["FN"] += 1
        
    def writeRankingToFile(self):
        if self.alertCounter == self.lastAlertCounter or self.alertCounter == 0:
            thread2 = Timer(60, self.writeRankingToFile)
            thread2.start()
            return
        self.numberOfRankings += 1
        p = Path('Detections' + self.fileString)
        q = p / 'Correlation' 
        if not q.exists():
            q.mkdir(parents=True)
        rankingFile = open(str(q) + "/RankingAttackType.csv", "a")
        rankingFile.write("Position,sTime,eTime,Gateways,Deviation_score,Attack_type,Real_labels")
        line = ""
        position = 0
        alerts = list(self.ranking)
        for alert in alerts:
            line += "\n"
            line += str(position) + ","
            line += alert['sTime'].strftime("%Y-%m-%dT%H:%M:%SZ") + ","
            line += alert['eTime'].strftime("%Y-%m-%dT%H:%M:%SZ") + ","
            line += str(alert['Gateways']) + ","
            line += str(alert['Deviation_score']) + ","
            line += str(alert['Attack_types']) + ","
            line += str(alert['Real_labels'])
        
            if '1' not in alert['Real_labels']:
                self.falsePositivesOut += 1
            elif '0' not in alert['Real_labels']:
                self.truePositivesOut += 1
            else:
                if alert['Real_labels']['0'] > alert['Real_labels']['1']:
                    self.falsePositivesOut += 1
                elif alert['Real_labels']['0'] < alert['Real_labels']['1']:
                    self.truePositivesOut += 1
            if position <= 10:
                if '1' not in alert['Real_labels']:
                    self.highRankingFalsePositives += alert['Real_labels']['0']
                    self.highRankingFalsePositivesWeighted += alert['Real_labels']['0']*alert['Weight']
                elif '0' not in alert['Real_labels']:
                    self.highRankingTruePositives += alert['Real_labels']['1']
                    self.highRankingTruePositivesWeighted += alert['Real_labels']['1']*alert['Weight']
                else:
                    self.highRankingFalsePositives += alert['Real_labels']['0']
                    self.highRankingTruePositives += alert['Real_labels']['1']
                    self.highRankingTotal += alert['Real_labels']['0'] + alert['Real_labels']['1']

                    self.highRankingFalsePositivesWeighted += alert['Real_labels']['0']*alert['Weight']
                    self.highRankingTruePositivesWeighted += alert['Real_labels']['1']*alert['Weight']
                    self.highRankingTotalWeighted += alert['Real_labels']['0'] + alert['Real_labels']['1']*alert['Weight']
            self.findPerformance( alert['Real_labels'],  alert['sTime'].strftime("%Y-%m-%dT%H:%M:%SZ"),  alert['eTime'].strftime("%Y-%m-%dT%H:%M:%SZ"), 1)

            counter = 0
            nowInterval = pd.Interval(pd.Timestamp(alert['sTime']), pd.Timestamp(alert['eTime']))
            for attackInterval in self.attackIntervals:
                if attackInterval.overlaps(nowInterval) and '1' in alert['Real_labels']:
                    self.detectedAttacks[counter] = True
                counter += 1

            position +=1
        line += "\n"
        line += "\n"
        rankingFile.write(line)
        rankingFile.close()

        rankingFile = open(str(q) + "/RankingDeviationScore.csv", "a")
        rankingFile.write("Position,sTime,eTime,Gateways,Deviation_score,Attack_type,Real_labels")
        line = ""
        position = 0
        alerts = list(self.rankingDeviationScore)
        for alert in alerts:
            line += "\n"
            line += str(position) + ","
            line += alert['sTime'].strftime("%Y-%m-%dT%H:%M:%SZ") + ","
            line += alert['eTime'].strftime("%Y-%m-%dT%H:%M:%SZ") + ","
            line += str(alert['Gateways']) + ","
            line += str(alert['Deviation_score']) + ","
            line += str(alert['Attack_types']) + ","
            line += str(alert['Real_labels'])
        
            if '1' not in alert['Real_labels']:
                self.falsePositivesOutDs += 1
            elif '0' not in alert['Real_labels']:
                self.truePositivesOutDs += 1
            else:
                if alert['Real_labels']['0'] > alert['Real_labels']['1']:
                    self.falsePositivesOutDs += 1
                elif alert['Real_labels']['0'] < alert['Real_labels']['1']:
                    self.truePositivesOutDs += 1
            if position <= 10:
                if '1' not in alert['Real_labels']:
                    self.highRankingFalsePositivesDs += alert['Real_labels']['0']
                    self.highRankingFalsePositivesWeightedDs += alert['Real_labels']['0']*alert['Weight']
                elif '0' not in alert['Real_labels']:
                    self.highRankingTruePositivesDs += alert['Real_labels']['1']
                    self.highRankingTruePositivesWeightedDs += alert['Real_labels']['1']*alert['Weight']
                else:
                    self.highRankingFalsePositivesDs += alert['Real_labels']['0']
                    self.highRankingTruePositivesDs += alert['Real_labels']['1']
                    self.highRankingTotalDs += alert['Real_labels']['0'] + alert['Real_labels']['1']

                    self.highRankingFalsePositivesWeightedDs += alert['Real_labels']['0']*alert['Weight']
                    self.highRankingTruePositivesWeightedDs += alert['Real_labels']['1']*alert['Weight']
                    self.highRankingTotalWeightedDs += alert['Real_labels']['0'] + alert['Real_labels']['1']*alert['Weight']

            position +=1
        line += "\n"
        line += "\n"
        rankingFile.write(line)
        rankingFile.close()

        print("Wrote ranking to file")
        self.lastAlertCounter = self.alertCounter
        thread2 = Timer(60, self.writeRankingToFile)
        thread2.start()

    def sortByAttackType(self, values):
        def priority_getter(value):
            priority = {
                "Flooding": 1,
                "ICMP Flood": 2,
                "SYN Flood": 3,
                "Same protocol": 4,
                "Xmas": 5,
                "Low-Rate": 6,
                "Different protocols": 7, 
                "": 8
            }
        
            highestKey = max(value["Attack_types"], key= lambda x: value["Attack_types"][x])

            if highestKey == "" and len(value["Attack_types"]) > 1:
                newValue = dict((i,value["Attack_types"][i]) for i in value["Attack_types"] if i!="")
                highestKey = max(newValue, key= lambda x: newValue[x])
            
            return priority.get(highestKey)

        return sorted(values, key=priority_getter)

    def rank(self, stime, etime, gateways, deviation_scores, real_labels, attack_types, weight):
        deviation_scores = list(filter(lambda x: x is not None, deviation_scores))

        stime = datetime.strptime(stime, "%Y-%m-%dT%H:%M:%SZ")
        etime = datetime.strptime(etime, "%Y-%m-%dT%H:%M:%SZ")

        if len(self.ranking) > 0:
            newRanking = []
            
            for alert in self.ranking:
                if alert['sTime'] > stime - timedelta(minutes=15):
                    newRanking.append(alert)
            if len(deviation_scores) > 2:
                newAlert = {
                            "sTime": stime,
                            "eTime": etime,
                            "Gateways": gateways,
                            "Deviation_score": {"mean": np.nanmean(deviation_scores), "standard_deviation": np.nanstd(deviation_scores)},
                            "Real_labels": real_labels,
                            "Attack_types": attack_types,
                            "Weight": weight
                            }
            else:
                newAlert = {
                            "sTime": stime,
                            "eTime": etime,
                            "Gateways": gateways,
                            "Deviation_score": {"mean": np.nanmean(deviation_scores)},
                            "Real_labels": real_labels,
                            "Attack_types": attack_types,
                            "Weight": weight
                            }

            newRanking.append(newAlert)
            rankingBasedOnDeviationScore = self.sortByAttackType(newRanking)
            rankingBasedOnDeviationScore = sorted(rankingBasedOnDeviationScore, key=lambda x: x["Deviation_score"]["mean"], reverse=True)
            newRanking = sorted(newRanking, key=lambda x: x["Deviation_score"]["mean"], reverse=True)
            newRanking = self.sortByAttackType(newRanking)
            self.ranking = newRanking
            self.rankingDeviationScore = rankingBasedOnDeviationScore
        else:
            if len(deviation_scores) > 2:
                newAlert = {
                        "sTime": stime,
                        "eTime": etime,
                        "Gateways": gateways,
                        "Deviation_score": {"mean": np.nanmean(deviation_scores), "standard_deviation": np.nanstd(deviation_scores)},
                        "Real_labels": real_labels,
                        "Attack_types": attack_types,
                            "Weight": weight
                        }
            else:
                newAlert = {
                        "sTime": stime,
                        "eTime": etime,
                        "Gateways": gateways,
                        "Deviation_score": {"mean": np.nanmean(deviation_scores)},
                        "Real_labels": real_labels,
                        "Attack_types": attack_types,
                            "Weight": weight
                        }
            self.ranking.append(newAlert)
    """
        The MQTT commands are listened to and appropriate actions are taken for each.
    """
    def on_connect(self, client, userdata, flags, rc):
        print("Connected with result code "+str(rc))
        self.mqtt_client.subscribe(self.input)

    def on_publish(self, client, userdata, result):
        print("Ranking published to topic", self.output)
    
    def on_message(self, client, userdata, msg):
        print('Incoming message to topic {}'.format(msg.topic))
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
        except Exception as err:
            print('Message sent to topic {} had no valid JSON. Message ignored. {}'.format(msg.topic, err))
            return

        if payload.get('sTime') == "WRITE":
            p = Path('Detections' + self.fileString)
            q = p / 'Correlation' 
            if not q.exists():
                q.mkdir(parents=True)
            alertsFile = open(str(q) + "/NumberOfAlertsRankingAttackTypes.csv", "a")
            if self.highRankingTruePositives == 0:
                precision = 0
            elif self.highRankingFalsePositives == 0:
                precision = 1
            else:
                precision = self.highRankingTruePositives/(self.highRankingTruePositives + self.highRankingFalsePositives)

            if self.highRankingTruePositivesWeighted == 0:
                weightedPrecision = 0
            elif self.highRankingFalsePositivesWeighted == 0:
                weightedPrecision = 1
            else:
                weightedPrecision = self.highRankingTruePositivesWeighted/(self.highRankingTruePositivesWeighted + self.highRankingFalsePositivesWeighted)
            alertsFile.write("NumberOfAlertsIn,NumberOfRankings,TPin,FPin,TPout,FPout,highRankingPrecision,weightedHighRankingPrecision")
            alertsFile.write("\n" + str(self.alertCounter) +"," + str(self.numberOfRankings) + "," +str(self.truePositivesIn) + ","+ str(self.falsePositivesIn)+"," + str(self.truePositivesOut) + ","+ str(self.falsePositivesOut) + "," + str(precision) + "," +str(weightedPrecision))
            alertsFile.close()

            alertsFile = open(str(q) + "/NumberOfAlertsRankingDeviationScore.csv", "a")
            if self.highRankingTruePositivesDs == 0:
                precision = 0
            elif self.highRankingFalsePositivesDs == 0:
                precision = 1
            else:
                precision = self.highRankingTruePositivesDs/(self.highRankingTruePositivesDs + self.highRankingFalsePositivesDs)

            if self.highRankingTruePositivesWeightedDs == 0:
                weightedPrecision = 0
            elif self.highRankingFalsePositivesWeightedDs == 0:
                weightedPrecision = 1
            else:
                weightedPrecision = self.highRankingTruePositivesWeightedDs/(self.highRankingTruePositivesWeightedDs + self.highRankingFalsePositivesWeightedDs)
            alertsFile.write("NumberOfAlertsIn,NumberOfRankings,TPin,FPin,TPout,FPout,highRankingPrecision,weightedHighRankingPrecision")
            alertsFile.write("\n" + str(self.alertCounter) +"," + str(self.numberOfRankings) + "," +str(self.truePositivesIn) + ","+ str(self.falsePositivesIn)+"," + str(self.truePositivesOutDs) + ","+ str(self.falsePositivesOutDs) + "," + str(precision) + "," +str(weightedPrecision))
            alertsFile.close()
            

            alertsFile = open(str(q) + "/DetectionAttackTypesRanking.csv", "a")
            alertsFile.write(",".join(attackType for attackType in self.attacks))
            alertsFile.write("\n")
            alertsFile.write(",".join(str(i) for i in self.detectedAttacks))
            alertsFile.close()

            attackScores = open(str(q) + "/ScoresAttackTypes.Ranking.json", "w")
            json.dump(self.attackDict,attackScores)
            attackScores.close()
        else:
            self.alertCounter += 1
            stime = payload.get('sTime')
            etime = payload.get('eTime')
            gateways = payload.get('Gateways')
            deviation_scores = payload.get('Deviation_scores')
            real_labels = payload.get('Real_labels')
            attack_types = payload.get('Attack_types')
            weight = payload.get('Weight')
            self.rank(stime, etime, gateways, deviation_scores, real_labels, attack_types, weight)
            if '1' not in real_labels:
                self.falsePositivesIn += 1
            elif '0' not in real_labels:
                self.truePositivesIn += 1
            else:
                if real_labels['0'] > real_labels['1']:
                    self.falsePositivesIn += 1
                elif real_labels['0'] < real_labels['1']:
                    self.truePositivesIn += 1

    def start(self):
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_message = self.on_message
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_publish = self.on_publish
        
        self.mqtt_client.connect(self.broker, self.port)
        try:
            self.mqtt_client.loop_start()
            thread2 = Timer(60, self.writeRankingToFile)
            thread2.start()
            
        except:
            print("Interrupted")
            
            self.mqtt_client.disconnect()
