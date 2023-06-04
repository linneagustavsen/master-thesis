from datetime import datetime, timedelta
from pathlib import Path
import statistics
import numpy as np
import pandas as pd
from Correlation.NetworkGraph import NetworkGraph
import paho.mqtt.client as mqtt
from threading import Thread
import json
from HelperFunctions.IsAttack import *

#Parameters for the MQTT connection
MQTT_BROKER = 'localhost'
MQTT_PORT = 1883
MQTT_USER = 'aggregation'
MQTT_PASSWORD = 'aggregationPass'
MQTT_TOPIC_INPUT = 'detections/correlation'
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
        self.alertCounter = 0
        self.truePositivesIn = 0
        self.falsePositivesIn = 0
        self.truePositivesOut = 0
        self.falsePositivesOut = 0
        self.highRankingFalsePositives = 0
        self.highRankingTruePositives = 0
        self.highRankingTotal = 0
        self.victim = victim
        self.victim6 = victim6
        self.ip_addresses = ip_addresses
        self.ipv6_addresses = ipv6_addresses

    def writeIPToRanking(self, ip):
        if ip == victim:
            return "Victim"
        elif ip == victim6:
            return "Victim"
        elif ip in ip_addresses:
            return "Attacker"
        elif ip in ipv6_addresses:
            return "Attacker"
        else:
            return "Normal"

    def writeRankingToFile(self):
        p = Path('Detections' + self.fileString)
        q = p / 'Correlation' 
        if not q.exists():
            q.mkdir(parents=True)
        rankingFile = open(str(q) + "/RankingStdev.csv", "a")
        rankingFile.write("Position,sTime,eTime,IP,Gateways,Deviation_score,Attack_type,Real_labels")
        line = ""
        position = 0
        for alert in self.ranking:
            line += "\n"
            line += str(position) + ","
            line += alert['sTime'].strftime("%Y-%m-%dT%H:%M:%SZ") + ","
            line += alert['eTime'].strftime("%Y-%m-%dT%H:%M:%SZ") + ","
            line += str(self.writeIPToRanking(alert['IP'])) + ","
            line += str(alert['Gateways']) + ","
            line += str(alert['Deviation_score']) + ","
            line += str(alert['Attack_types']) + ","
            line += str(alert['Real_labels'])
        
            
            if alert['Real_labels']['0'] > alert['Real_labels']['1']:
                self.falsePositivesOut += 1
            elif alert['Real_labels']['0'] < alert['Real_labels']['1']:
                self.truePositivesOut += 1
            if position <= 10:
                self.highRankingFalsePositives += alert['Real_labels']['0']
                self.highRankingTruePositives += alert['Real_labels']['1']
                self.highRankingTotal += alert['Real_labels']['0'] + alert['Real_labels']['1']

            position +=1
        line += "\n"
        line += "\n"
        rankingFile.write(line)
        rankingFile.close()


    def sortByAttackType(self, values):
        def priority_getter(value):
            priority = {
                "Flooding": 1,
                "ICMP Flood": 2,
                "SYN Flood": 3,
                "Same": 4,
                "Xmas": 5,
                "Low-Rate": 6,
                "Different": 7, 
                "": 8
            }
        
            highestKey = max(value["Attack_types"], key= lambda x: value["Attack_types"][x])

            if highestKey == "" and len(value["Attack_types"]) > 1:
                newValue = dict((i,value["Attack_types"][i]) for i in value["Attack_types"] if i!="")
                highestKey = max(newValue, key= lambda x: newValue[x])
            
            return priority.get(highestKey)

        return sorted(values, key=priority_getter)

    def rank(self, stime, etime, ip, gateways, deviation_scores, real_labels, attack_types):
        deviation_scores = list(filter(lambda x: x is not None, deviation_scores))
        if real_labels['0'] > real_labels['1']:
            self.falsePositivesIn += 1
        elif real_labels['0'] < real_labels['1']:
            self.truePositivesIn += 1
        stime = datetime.strptime(stime, "%Y-%m-%dT%H:%M:%SZ")
        etime = datetime.strptime(etime, "%Y-%m-%dT%H:%M:%SZ")

        if len(deviation_scores) > 2:
            newAlert = {
                        "sTime": stime,
                        "eTime": etime,
                        "Gateways": gateways,
                        "IP": ip,
                        "Deviation_score": {"mean": np.nanmean(deviation_scores), "standard_deviation": statistics.stdev(deviation_scores)},
                        "Real_labels": real_labels,
                        "Attack_types": attack_types
                        }
        else:
            newAlert = {
                    "sTime": stime,
                    "eTime": etime,
                    "Gateways": gateways,
                    "IP": ip,
                    "Deviation_score": {"mean": np.nanmean(deviation_scores)},
                    "Real_labels": real_labels,
                    "Attack_types": attack_types
                    }
        if len(self.ranking) > 0:
            self.ranking.append(newAlert)
            self.ranking = sorted(self.ranking, key=lambda x: x["Deviation_score"]["mean"], reverse=True)
            self.ranking = self.sortByAttackType(self.ranking)
        else:
            self.ranking.append(newAlert)
        

    def start(self):
        with open('IPCalculations/Correlation/correlatedIPAlerts.txt', 'r') as convert_file:
            for line in convert_file:
                payload = json.loads(line)
                stime = payload.get('sTime')
                etime = payload.get('eTime')
                ip = payload.get('IP')
                gateways = payload.get('Gateways')
                deviation_scores = payload.get('Deviation_scores')
                real_labels = payload.get('Real_labels')
                attack_types = payload.get('Attack_types')
                self.rank(stime, etime,ip, gateways, deviation_scores, real_labels, attack_types)
        self.writeRankingToFile()
        print("Wrote ranking to file")
        p = Path('Detections' + self.fileString)
        q = p / 'Correlation' 
        if not q.exists():
            q.mkdir(parents=True)
        alertsFile = open(str(q) + "/NumberOfAlertsRanking.csv", "a")
        precision = self.highRankingTruePositives/self.highRankingFalsePositives 
        alertsFile.write("NumberOfAlertsIn,NumberOfRankings,TPin,FPin,TPout,FPout,highRankingPrecision\n" + str(self.alertCounter) +"," + str(self.numberOfRankings) + "," +str(self.truePositivesIn) + ","+ str(self.falsePositivesIn)+"," + str(self.truePositivesOut) + ","+ str(self.falsePositivesOut) + "," + str(precision))
        alertsFile.close()