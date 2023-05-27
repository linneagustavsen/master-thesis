import datetime
import math
from pathlib import Path
import pandas as pd
import paho.mqtt.client as mqtt
from threading import Thread
import json
from datetime import timedelta

from HelperFunctions.Normalization import normalization

#Parameters for the MQTT connection
MQTT_BROKER = 'localhost'
MQTT_PORT = 1883
MQTT_USER = 'correlation'
MQTT_PASSWORD = 'correlationPass'
MQTT_TOPIC_INPUT = 'detections/aggregation/ips'
MQTT_TOPIC_OUTPUT = 'detections/correlation'

"""
    This class is for correlating alerts
"""
class Correlation_IPs:
    def __init__(self, broker, port, inputTopic, outputTopic, interval):
        self.port = port
        self.broker = broker
        self.input = inputTopic
        self.output = outputTopic
        self.alertsIP ={}
        self.alertCounter = 0
        self.interval = interval

    def countElements(self, listOfElements):
        counter = {}
        for element in listOfElements:
            if element in counter:
                counter[element] += 1
            else:
                counter[element] = 1
        return counter

    def addAlertsIP(self, ip, interval, alert):
        if ip in self.alertsIP:
            if interval in self.getTimesAlertsIP(ip):
                self.alertsIP[ip][interval].append(alert)
            else:
                self.alertsIP[ip][interval]= [alert]
        else:
                self.alertsIP[ip] = {interval:[alert]}

    def getTimesAlertsIP(self, ip):
        return self.alertsIP[ip]
    
    def getAlertsIP(self, ip, interval):
        return self.alertsIP[ip][interval]
    
    def removeTimestampFromIP(self, ip, interval):
        del self.alertsIP[ip][interval]

    def writeCorrelationToFile(self, message):
        with open('IPCalculations/Correlation/correlatedIPAlerts.txt', 'a') as file:
            file.write(json.dumps(message)+ '\n')

    def correlateIPs(self, stime, etime, ip, payload):
        stime = pd.Timestamp(stime)
        etime = pd.Timestamp(etime)
        fuzzyStartTime = stime - timedelta(minutes = 15)
        interval = pd.Interval(fuzzyStartTime, etime, closed='both')

        if ip in self.alertsIP:
            exists = False
            existingTimes = []
            overlappingAlerts = 1
            gateways = [payload.get('Gateway')]
            deviation_scores = []
            real_labels = []
            attack_types = []

            for time in self.getTimesAlertsIP(ip):
                if interval.overlaps(time):
                    exists = True
                    existingTimes.append(time)
                    alerts = self.getAlertsIP(ip, time)
                    overlappingAlerts += len(alerts)

                    for alert in alerts:
                        gateways.append(alert['Gateway'])
                        deviation_scores.append(alert["Deviation_score"])
                        real_labels.append(alert["Real_label"])
                        attack_types.append(alert["Attack_type"])

            if exists:
                for existingTime in existingTimes:
                    self.addAlertsIP(ip, existingTime, payload)
   
                if overlappingAlerts > 3:
                    
                    message = { 'sTime': stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                'eTime': etime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                'IP': ip,
                                'Gateways': list(set(gateways)),
                                'Deviation_scores': deviation_scores,
                                'Real_labels': self.countElements(real_labels),
                                'Attack_types': self.countElements(attack_types)
                                }
                
                    self.writeCorrelationToFile(message)
            else:
                self.addAlertsIP(ip, interval, payload)
        else:
            self.addAlertsIP(ip, interval, payload)
    
    def start(self):
        systems = ["bergen-gw3", "hoytek-gw2", "hovedbygget-gw", "trd-gw", "teknobyen-gw2", "teknobyen-gw1", "ifi2-gw5", 
            "oslo-gw1", "tromso-gw5", "stangnes-gw", "rodbergvn-gw2", "narvik-kv-gw", "narvik-gw3", "tromso-fh-gw",
            "ma2-gw", "narvik-gw4"]

        attackDate = "24.03.23"
        for systemId in systems:
            synData = pd.read_csv("IPCalculations/Threshold/NetFlow/SYN.attack.24.03.23."+str(systemId)+ ".csv")
            sTime = pd.to_datetime(synData["sTime"])
            eTime = pd.to_datetime(synData["eTime"])

            srcIP = synData["srcIP"]
            dstIP = synData["srcIP"]
            real_label = synData["real_label"]
            deviation = synData["Deviation_score"]

            for i in range(len(sTime)):
                sTime[i] = sTime[i].replace(tzinfo=None)
                eTime[i] = eTime[i].replace(tzinfo=None)
                if deviation[i] == "None":
                    deviation[i] = None
                payload = {
                        "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "Deviation_score": deviation[i],
                        "srcIP": int(srcIP[i]),
                        "dstIP": int(dstIP[i]),
                        "Real_label": int(real_label[i]),
                        "Attack_type": "SYN Flood"
                        }
                self.correlateIPs(sTime[i], sTime[i], srcIP[i], payload)
                self.correlateIPs(sTime[i], sTime[i], dstIP[i], payload)

            xmasData = pd.read_csv("IPCalculations/Threshold/NetFlow/Xmas.attack.24.03.23."+str(systemId)+ ".csv")
            sTime = pd.to_datetime(xmasData["sTime"])
            eTime = pd.to_datetime(xmasData["eTime"])

            srcIP = xmasData["srcIP"]
            dstIP = xmasData["srcIP"]
            real_label = xmasData["real_label"]

            for i in range(len(sTime)):
                sTime[i] = sTime[i].replace(tzinfo=None)
                eTime[i] = eTime[i].replace(tzinfo=None)
                payload = {
                        "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "Deviation_score": None,
                        "srcIP": int(srcIP[i]),
                        "dstIP": int(dstIP[i]),
                        "Real_label": int(real_label[i]),
                        "Attack_type": "Xmas"
                        }
                self.correlateIPs(sTime[i], sTime[i], srcIP[i], payload)
                self.correlateIPs(sTime[i], sTime[i], dstIP[i], payload)

            topKflowsData = pd.read_csv("IPCalculations/TopKFlows/NetFlow/TopFlowChange.attack.24.03.23."+str(systemId)+ ".csv")
            sTime = pd.to_datetime(topKflowsData["sTime"])
            eTime = pd.to_datetime(topKflowsData["eTime"])

            srcIP = topKflowsData["srcIP"]
            dstIP = topKflowsData["srcIP"]
            real_label = topKflowsData["real_label"]
            deviation = topKflowsData["Deviation_score"]

            for i in range(len(sTime)):
                sTime[i] = sTime[i].replace(tzinfo=None)
                eTime[i] = eTime[i].replace(tzinfo=None)
                if deviation[i] == "None":
                    deviation[i] = None
                payload = {
                        "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "Deviation_score": deviation[i],
                        "srcIP": int(srcIP[i]),
                        "dstIP": int(dstIP[i]),
                        "Real_label": int(real_label[i]),
                        "Attack_type": "Flooding"
                        }
                self.correlateIPs(sTime[i], sTime[i], srcIP[i], payload)
                self.correlateIPs(sTime[i], sTime[i], dstIP[i], payload)


            attackClusterFields = pd.read_csv("IPCalculations/Kmeans/NetFlow/Fields.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")   
            sTime = pd.to_datetime(attackClusterFields["sTime"])
            eTime = pd.to_datetime(attackClusterFields["eTime"])

            srcIP = attackClusterFields["srcIP"]
            dstIP = attackClusterFields["srcIP"]
            real_label = attackClusterFields["real_label"]
            attackType = attackClusterFields["attackType"]
            for i in range(len(sTime)):
                sTime[i] = sTime[i].replace(tzinfo=None)
                eTime[i] = eTime[i].replace(tzinfo=None)

                payload = {
                        "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "Deviation_score": None,
                        "srcIP": int(srcIP[i]),
                        "dstIP": int(dstIP[i]),
                        "Real_label": int(real_label[i]),
                        "Attack_type": attackType[i]
                        }
                self.correlateIPs(sTime[i], sTime[i], srcIP[i], payload)
                self.correlateIPs(sTime[i], sTime[i], dstIP[i], payload)
            attackClusterCombined = pd.read_csv("IPCalculations/Kmeans/NetFlow/Combined."+ str(int(self.interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
            sTime = pd.to_datetime(attackClusterCombined["sTime"])
            eTime = pd.to_datetime(attackClusterCombined["eTime"])

            srcIP = attackClusterCombined["srcIP"]
            dstIP = attackClusterCombined["srcIP"]
            real_label = attackClusterCombined["real_label"]
            attackType = attackClusterCombined["attackType"]
            for i in range(len(sTime)):
                sTime[i] = sTime[i].replace(tzinfo=None)
                eTime[i] = eTime[i].replace(tzinfo=None)

                payload = {
                        "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "Deviation_score": None,
                        "srcIP": int(srcIP[i]),
                        "dstIP": int(dstIP[i]),
                        "Real_label": int(real_label[i]),
                        "Attack_type": attackType[i]
                        }
                self.correlateIPs(sTime[i], sTime[i], srcIP[i], payload)
                self.correlateIPs(sTime[i], sTime[i], dstIP[i], payload)
            randomForestCombined = pd.read_csv("IPCalculations/Kmeans/NetFlow/Alerts.Combined."+ str(int(self.interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
            sTime = pd.to_datetime(randomForestCombined["sTime"])
            eTime = pd.to_datetime(randomForestCombined["eTime"])

            srcIP = randomForestCombined["srcIP"]
            dstIP = randomForestCombined["srcIP"]
            real_label = randomForestCombined["real_label"]

            for i in range(len(sTime)):
                sTime[i] = sTime[i].replace(tzinfo=None)
                eTime[i] = eTime[i].replace(tzinfo=None)

                payload = {
                        "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "Deviation_score": None,
                        "srcIP": int(srcIP[i]),
                        "dstIP": int(dstIP[i]),
                        "Real_label": int(real_label[i]),
                        "Attack_type": ""
                        }
                self.correlateIPs(sTime[i], sTime[i], srcIP[i], payload)
                self.correlateIPs(sTime[i], sTime[i], dstIP[i], payload)
            randomForestFields = pd.read_csv("IPCalculations/Kmeans/NetFlow/Alerts.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
            sTime = pd.to_datetime(randomForestFields["sTime"])
            eTime = pd.to_datetime(randomForestFields["eTime"])

            srcIP = randomForestFields["srcIP"]
            dstIP = randomForestFields["srcIP"]
            real_label = randomForestFields["real_label"]

            for i in range(len(sTime)):
                sTime[i] = sTime[i].replace(tzinfo=None)
                eTime[i] = eTime[i].replace(tzinfo=None)

                payload = {
                        "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "Deviation_score": None,
                        "srcIP": int(srcIP[i]),
                        "dstIP": int(dstIP[i]),
                        "Real_label": int(real_label[i]),
                        "Attack_type": ""
                        }
                self.correlateIPs(sTime[i], sTime[i], srcIP[i], payload)
                self.correlateIPs(sTime[i], sTime[i], dstIP[i], payload)
    