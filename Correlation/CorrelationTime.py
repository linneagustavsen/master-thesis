import pandas as pd
from Correlation.NetworkGraph import NetworkGraph
import paho.mqtt.client as mqtt
import networkx as nx
from threading import Thread
import json
from datetime import datetime, timedelta
from datetime import date

#Parameters for the MQTT connection
MQTT_BROKER = 'mosquitto'
MQTT_PORT = 1883
MQTT_USER = 'correlation'
MQTT_PASSWORD = 'correlationPass'
MQTT_TOPIC_INPUT = 'detections/aggregation/time'
MQTT_TOPIC_OUTPUT = 'detections/correlation'

"""
    This class is for correlating alerts
"""
class Correlation_Time:
    def __init__(self, broker, port, inputTopic, outputTopic, graph):
        self.port = port
        self.broker = broker
        self.input = inputTopic
        self.output = outputTopic
        self.graph = graph
        self.alertsCorrelated = {}

    def correlateTime(self, stime, etime, gateway, deviation_scores, real_labels, attack_types, alertDB):
        #for gateway, timestamps in payload:
            #If gateway1 is close to gateway2 and they have the same fuzzy timestamps
                #look at attack types
                #(look at IPs, ports, protocol)
                #If they are the same
                    #generate an alert for that time, that attack type, and the highest deviation score (or the mean)
                    #send the alert to the alert ranking

        exists = False
        existsCorrelated = False
        gateways = [gateway]
        stime = pd.Timestamp(stime)
        etime = pd.Timestamp(etime)
        fuzzyStartTime = stime - timedelta(seconds = 30)
        interval = pd.Interval(fuzzyStartTime, etime, closed='left')
        for otherGateway in self.graph:
            if otherGateway == gateway:
                continue
            if nx.shortest_path_length(self.graph, gateway, otherGateway) < 4:
                for time, alerts in alertDB[otherGateway]:
                    if interval.overlaps(time):
                        exists = True
                        gateways.append(otherGateway)
                        for alert in alerts:
                            deviation_scores.append(alert["Deviation_score"])
                            real_labels.append(alert["Real_label"])
                            attack_types.append(alert["Attack_type"])

        for time, alerts in self.alertsCorrelated:
            if interval.overlaps(time):
                existsCorrelated = True
                for alert in alerts:
                    gateways.extend(alert['Gateways'])
                    deviation_scores.extend(alert["Deviation_scores"])
                    real_labels.extend(alert["Real_labels"])
                    attack_types.extend(alert["Attack_types"])
                    
        alert = {
                    "sTime": stime,
                    "eTime": etime,
                    "Gateways": gateways,
                    "Deviation_scores": deviation_scores,
                    "Real_labels": real_labels,
                    "Attack_type": attack_types
                    }             
        if exists and existsCorrelated:
            self.alertsCorrelated[interval].append(alert)
            self.mqtt_client.publish(self.output, json.dumps(alert))
        elif exists:
            self.alertsCorrelated[interval] = [alert]
            self.mqtt_client.publish(self.output, json.dumps(alert))
        elif existsCorrelated:
            self.alertsCorrelated[interval].append(alert)
            self.mqtt_client.publish(self.output, json.dumps(alert))
        else:
            self.alertsCorrelated[interval] = [alert]

    """
        The MQTT commands are listened to and appropriate actions are taken for each.
    """
    def on_connect(self, client, userdata, flags, rc):
        print("Connected with result code "+str(rc))
        self.mqtt_client.subscribe(self.input)

    def on_publish(self, client, userdata, result):
        print("Aggregation published to topic", self.input)
    
    def on_message(self, client, userdata, msg):
        print('Incoming message to topic {}'.format(msg.topic))
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
            print(payload)
        except Exception as err:
            print('Message sent to topic {} had no valid JSON. Message ignored. {}'.format(msg.topic, err))
            return

        stime = payload.get('sTime')
        etime = payload.get('eTime')
        gateway = payload.get('Gateway')
        deviation_scores = payload.get('Deviation_scores')
        real_labels = payload.get('Real_labels')
        attack_types = payload.get('Attack_types')
        alertDB = payload.get('alertDB')

        self.correlateTime(stime, etime, gateway, deviation_scores, real_labels, attack_types, alertDB)

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
            self.mqtt_client.disconnect()

graph = NetworkGraph()
correlation = Correlation_Time(MQTT_BROKER, MQTT_PORT, MQTT_TOPIC_INPUT, MQTT_TOPIC_OUTPUT, graph)
correlation.start()