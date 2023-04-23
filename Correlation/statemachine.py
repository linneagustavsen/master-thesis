import stmpy
import paho.mqtt.client as mqtt
import networkx as nx
from threading import Thread
import json
from datetime import datetime, timedelta
from datetime import date

#Parameters for the MQTT connection
MQTT_BROKER = 'mosquitto'
MQTT_PORT = 1883
MQTT_USER = 'aggregation'
MQTT_PASSWORD = 'aggregationPass'
MQTT_TOPIC_INPUT = 'detections/modules/#'
MQTT_TOPIC_OUTPUT = 'detections/correlation'

"""
    This class is for aggregating and correlating alerts
"""
class Correlation_Sender:
    def __init__(self, correlation_mqtt, machineID):
        self.correlation_mqtt = correlation_mqtt
        self.machineID = machineID

    def sendMessageRanking(self, attackType, deviation_score, srcIP, dstIP, gateways):
        self.correlation_mqtt.mqtt_client.publish(MQTT_TOPIC_OUTPUT, json.dumps({"Attack_type": attackType, "Deviation_score": deviation_score, "srcIP": srcIP, "dstIP": dstIP, "Gateways": gateways}))
    
    def aggregateTime(self, stime, etime, gateway, payload):
        fuzzyStartTime = stime - timedelta(seconds = 30)
        exists = False
        existTime = datetime()
        for i in range(int((etime-fuzzyStartTime).total_seconds())+1):
            time = fuzzyStartTime + timedelta(seconds = i)
            if time.replace(microsecond=0) in self.correlation_mqtt.graph.getAlerts(gateway):
                exists = True
                existTime = time
        
        if exists:
            self.correlation_mqtt.graph.addAlertToGraph(gateway, existTime, payload)
            if len(self.correlation_mqtt.graph.getAlertsFromTimestamp(gateway, existTime)) > 3:
                deviation_scores = []
                real_labels = []
                attack_types = []
                for alert in self.correlation_mqtt.graph.getAlertsFromTimestamp(gateway, existTime):
                    deviation_scores.append(alert["Deviation_score"])
                    real_labels.append(alert["Real_label"])
                    attack_types.append(alert["Attack_type"])
                self.correlation_mqtt.driver.send('manyAlertsTime',self.machineID, args=[stime, etime, gateway, deviation_scores, real_labels, attack_types])
            else:
                self.correlation_mqtt.driver.send('notEnough',self.machineID)
        else:
            self.correlation_mqtt.graph.addTimestampToGraph(self, gateway, etime, payload)
            self.correlation_mqtt.driver.send('notEnough',self.machineID)
    
    def aggregateIPs(self, stime, etime, ip, payload):
        if ip in self.correlation_mqtt.alertsIP:
            fuzzyStartTime = stime - timedelta(minutes = 15)
            exists = False
            existTime = datetime()
            for i in range(int((etime-fuzzyStartTime).total_seconds())+1):
                time = fuzzyStartTime + timedelta(seconds = i)
                if time.replace(microsecond=0) in self.correlation_mqtt.getAlertsIP(ip):
                    exists = True
                    existTime = time
            if exists:
                self.correlation_mqtt.addAlertToExistingTimestampAlertsIP(ip, existTime, payload)
                if len(self.correlation_mqtt.getAlertsIP(ip, existTime)) > 10:
                    deviation_scores = []
                    real_labels = []
                    attack_types = []
                    for alert in self.correlation_mqtt.getAlertsIP(ip, existTime):
                        deviation_scores.append(alert["Deviation_score"])
                        real_labels.append(alert["Real_label"])
                        attack_types.append(alert["Attack_type"])
                    self.correlation_mqtt.driver.send('manyAlertsIPs',self.machineID, args=[stime, etime, ip, deviation_scores, real_labels, attack_types])
                else:
                    self.correlation_mqtt.driver.send('manyAlertsIPs',self.machineID)
            else:
                self.correlation_mqtt.addTimestampAndAlertToAlertsIP(ip, etime, payload)
                self.correlation_mqtt.driver.send('notEnough',self.machineID)
        else:
            self.correlation_mqtt.addAlertsIP(ip, etime, payload)
            self.correlation_mqtt.driver.send('notEnough',self.machineID)

    def correlateTime(self, stime, etime, gateway, deviation_scores, real_labels, attack_types):
        #for gateway, timestamps in payload:
            #If gateway1 is close to gateway2 and they have the same fuzzy timestamps
                #look at attack types
                #(look at IPs, ports, protocol)
                #If they are the same
                    #generate an alert for that time, that attack type, and the highest deviation score (or the mean)
                    #send the alert to the alert ranking



        exists = False
        existTimes = []
        gateways = []
        for otherGateway in self.correlation_mqtt.G.nodes:
            if otherGateway == gateway:
                continue
            if nx.shortest_path_length < 4:
                fuzzyStartTime = stime - timedelta(seconds = 30)
                for i in range(int((etime-fuzzyStartTime).total_seconds())+1):
                    time = fuzzyStartTime + timedelta(seconds = i)
                    if time.replace(microsecond=0) in self.correlation_mqtt.G.nodes[otherGateway]['alerts']:
                        exists = True
                        existTimes.append(time)
                
        if exists:
            alert = {
                "sTime": stime,
                "eTime": etime,
                "Deviation_score": deviation_scores,
                "Real_labels": real_labels,
                "Attack_type": attack_types
                }
            self.correlation_mqtt.alertsCorrelated[existTime.replace(microsecond=0)].append(alert)
            if len(self.correlation_mqtt.G.nodes[gateway]['alerts'][existTime.replace(microsecond=0)]) > 3:
                self.correlation_mqtt.driver.send('manyAlertsTime',self.machineID, args=[stime, etime, gateways])
            else:
                self.correlation_mqtt.driver.send('notEnough',self.machineID)
        else:
            self.G.nodes[gateway]['alerts'][etime.replace(microsecond=0)] = [payload]
            self.correlation_mqtt.driver.send('notEnough',self.machineID)

        self.correlation_mqtt.driver.send('suspicion',self.machineID, args=[])

    def correlateIPs(self, stime, etime, ip):

        self.correlation_mqtt.driver.send('suspicion',self.machineID, args=[])

t0 = {
    'source': 'initial',
    'target': 'idle'}

t1 = {
    'trigger': 'aggregateTime',
    'source': 'idle',
    'target': 'aggregation',
    'effect': 'aggregateTime(*)'} # Variables are passed to the state machines with the (*) notation.

t2 = {
    'trigger': 'aggregateIPs',
    'source': 'idle',
    'target': 'aggregation',
    'effect': 'aggregateIPs(*)'}

t3 = {
    'trigger': 'manyAlertsTime',
    'source': 'aggregation',
    'target': 'correlation',
    'effect': 'correlateTime(*)'}

t4 = {
    'trigger': 'manyAlertsIP',
    'source': 'aggregation',
    'target': 'correlation',
    'effect': 'correlateIPs(*)'}

t5 = {
    'trigger': 'suspicion',
    'source': 'correlation',
    'target': 'final',
    'effect': 'sendMessageRanking(*)'}

t6 = {
    'trigger': 'notEnough',
    'source': 'aggregation',
    'target': 'final'}


idle = {'name': 'idle'}
correlation = {'name': 'correlation'}
aggregation = {'name': 'aggregation'}
final = {'name': 'final'}

CorrelationStateMachineConfig = {
    'states': [idle, aggregation, correlation, final],
    'transitions' : [t0, t1, t2, t3, t4, t5, t6]
}
