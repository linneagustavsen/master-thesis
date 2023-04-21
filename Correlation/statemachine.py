import stmpy
import paho.mqtt.client as mqtt
import networkx as nx
from threading import Thread
import json
import random
from datetime import datetime, timedelta
from datetime import date

#Parameters for the MQTT connection
MQTT_BROKER = 'mosquitto'
MQTT_PORT = 1883
MQTT_USER = 'aggregation'
MQTT_PASSWORD = 'aggregationPass'
MQTT_TOPIC_INPUT = 'detections/modules/#'
MQTT_TOPIC_OUTPUT = 'detections/correlation'

class Correlation_MQTT:
    """
        The class is initialized with data fields and database dictionaries.
    """
    def __init__(self, broker, port, driver, inputTopic, outputTopic):
        self.driver = driver
        self.port = port
        self.broker = broker
        self.input = inputTopic
        self.output = outputTopic

        self.G = nx.Graph()
        self.G.add_nodes_from(["bergen-gw3", "bergen-gw4", "hoytek-gw2", "hovedbygget-gw", "trd-gw", "teknobyen-gw2", "teknobyen-gw1", "ifi2-gw5", "ifi2-gw", 
                    "oslo-gw1", "tromso-gw5", "stangnes-gw", "rodbergvn-gw2", "narvik-kv-gw", "narvik-gw3", "tromso-fh-gw",
                    "ma2-gw", "narvik-gw4", "tullin-gw2", "tullin-gw1"])
        self.G.add_edges_from([("trd-gw", "rodbergvn-gw2"),("narvik-kv-gw","trd-gw"), ("trd-gw", "teknobyen-gw2"), ("trd-gw", "oslo-gw1"), ("trd-gw", "hovedbygget-gw"),
                    ("teknobyen-gw2", "teknobyen-gw1"), ("teknobyen-gw2","ifi2-gw5"), ("narvik-kv-gw", "teknobyen-gw2"), ("narvik-kv-gw", "ifi2-gw5"), ("narvik-kv-gw", "stangnes-gw"),
                    ("narvik-kv-gw", "tromso-fh-gw"), ("narvik-kv-gw", "narvik-gw3"), ("narvik-kv-gw", "narvik-gw4"), ("tromso-fh-gw",  "ma2-gw"), ("tromso-fh-gw", "tromso-gw5"),
                    ("ma2-gw", "tromso-gw5"), ("ma2-gw","narvik-gw3"), ("ma2-gw", "narvik-gw4"), ("narvik-gw3", "narvik-gw4"), ("narvik-gw3", "hovedbygget-gw"), 
                    ("hovedbygget-gw", "tullin-gw2"), ("hovedbygget-gw", "hoytek-gw2"),("ifi2-gw5", "oslo-gw1"), ("ifi2-gw5", "ifi2-gw"), ("ifi2-gw", "bergen-gw4"),
                    ("ifi2-gw", "tullin-gw1"), ("ifi2-gw", "oslo-gw1"), ("oslo-gw1", "tullin-gw1"), ("tullin-gw1", "tullin-gw2"), ("tullin-gw2", "hoytek-gw2"),
                    ("tullin-gw1", "bergen-gw3"), ("rodbergvn-gw2", "stangnes-gw"), ("bergen-gw3", "bergen-gw4"), ("bergen-gw3", "hoytek-gw2"), ("narvik-kv-gw", "ifi2-gw"),
                    ("oslo-gw1", "narvik-kv-gw")])
        
        for node in self.G:
            self.G.nodes[node]['alerts'] = {}
        
        self.alertsIP ={}

        self.alertsCorrelated = {}
    
    def addAlertToGraph():
        self.correlation_mqtt.G.nodes[gateway]['alerts'][existTime.replace(microsecond=0)].append(payload)
        
    def on_connect(self, client, userdata, flags, rc):
        print("Connected with result code "+str(rc))
        self.mqtt_client.subscribe(self.input)

    """
        The MQTT commands are listened to and appropriate actions are taken for each.
    """
    #Function that is called when the sensor publish something to a MQTT topic
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

        self.driver.send('aggregateTime','Correlation', args=[stime, etime, gateway, payload])
        try:
            srcIP = payload.get('srcIP')
            dstIP = payload.get('dstIP')
            self.driver.send('aggregateIPs','Correlation', args=[stime, etime, srcIP, payload])
            self.driver.send('aggregateIPs','Correlation', args=[stime, etime, dstIP, payload])
        except Exception as err:
            print('Message sent to topic {} had no IP addresses. {}'.format(msg.topic, err))
            return

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

"""
    This class is for aggregating and correlating alerts
"""
class Correlation_Sender:
    def __init__(self, correlation_mqtt):
        self.correlation_mqtt = correlation_mqtt

    def sendMessageRanking(self, attackType, deviation_score, srcIP, dstIP, gateways):
        self.correlation_mqtt.mqtt_client.publish(MQTT_TOPIC_OUTPUT, json.dumps({"Attack_type": attackType, "Deviation_score": deviation_score, "srcIP": srcIP, "dstIP": dstIP, "Gateways": gateways}))
    
    def aggregateTime(self, stime, etime, gateway, payload):
        fuzzyStartTime = stime - timedelta(seconds = 30)
        exists = False
        existTime = datetime()
        for i in range(int((etime-fuzzyStartTime).total_seconds())+1):
            time = fuzzyStartTime + timedelta(seconds = i)
            if time.replace(microsecond=0) in self.correlation_mqtt.G.nodes[gateway]['alerts']:
                exists = True
                existTime = time
        
        if exists:
            self.correlation_mqtt.G.nodes[gateway]['alerts'][existTime.replace(microsecond=0)].append(payload)
            if len(self.correlation_mqtt.G.nodes[gateway]['alerts'][existTime.replace(microsecond=0)]) > 3:
                deviation_scores = []
                real_labels = []
                attack_types = []
                for alert in self.correlation_mqtt.G.nodes[gateway]['alerts'][existTime.replace(microsecond=0)]:
                    deviation_scores.append(alert["Deviation_score"])
                    real_labels.append(alert["Real_label"])
                    attack_types.append(alert["Attack_type"])
                self.self.correlation_mqtt.driver.send('manyAlertsTime','Correlation', args=[stime, etime, gateway, deviation_scores, real_labels, attack_types])
            else:
                self.self.correlation_mqtt.driver.send('notEnough','Correlation')
        else:
            self.G.nodes[gateway]['alerts'][etime.replace(microsecond=0)] = [payload]
            self.self.correlation_mqtt.driver.send('notEnough','Correlation')
    
    def aggregateIPs(self, stime, etime, ip, payload):
        if ip in self.correlation_mqtt.alertsIP:
            fuzzyStartTime = stime - timedelta(minutes = 15)
            exists = False
            existTime = datetime()
            for i in range(int((etime-fuzzyStartTime).total_seconds())+1):
                time = fuzzyStartTime + timedelta(seconds = i)
                if time.replace(microsecond=0) in self.correlation_mqtt.alertsIP[ip]:
                    exists = True
                    existTime = time
            if exists:
                self.correlation_mqtt.alertsIP[ip][existTime.replace(microsecond=0)].append(payload)
                if len(self.correlation_mqtt.alertsIP[ip][existTime.replace(microsecond=0)]) > 10:
                    deviation_scores = []
                    real_labels = []
                    attack_types = []
                    for alert in self.correlation_mqtt.alertsIP[ip][existTime.replace(microsecond=0)]:
                        deviation_scores.append(alert["Deviation_score"])
                        real_labels.append(alert["Real_label"])
                        attack_types.append(alert["Attack_type"])
                    self.self.correlation_mqtt.driver.send('manyAlertsIPs','Correlation', args=[stime, etime, ip, deviation_scores, real_labels, attack_types])
                else:
                    self.self.correlation_mqtt.driver.send('manyAlertsIPs','Correlation')
            else:
                self.alertsIP[ip][etime.replace(microsecond=0)] = [payload]
                self.self.correlation_mqtt.driver.send('notEnough','Correlation')
        else:
            self.self.correlation_mqtt.driver.send('notEnough','Correlation')

    def correlateTime(self, stime, etime, gateway, deviation_scores, real_labels, attack_types):
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
                self.self.correlation_mqtt.driver.send('manyAlertsTime','Correlation', args=[stime, etime, gateways])
            else:
                self.self.correlation_mqtt.driver.send('notEnough','Correlation')
        else:
            self.G.nodes[gateway]['alerts'][etime.replace(microsecond=0)] = [payload]
            self.self.correlation_mqtt.driver.send('notEnough','Correlation')

        self.correlation_mqtt.driver.send('suspicion','Correlation', args=[])

    def correlateIPs(self, stime, etime, ip):

        self.self.correlation_mqtt.driver.send('suspicion','Correlation', args=[])
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
    'target': 'idle',
    'effect': 'sendMessageRanking(*)'}

t6 = {
    'trigger': 'notEnough',
    'source': 'aggregation',
    'target': 'idle'}


idle = {'name': 'idle'}

correlation = {'name': 'correlation'}
aggregation = {'name': 'aggregation'}

driver = stmpy.Driver()
correlation_mqtt = Correlation_MQTT(MQTT_BROKER, MQTT_PORT, driver, MQTT_TOPIC_INPUT, MQTT_TOPIC_OUTPUT)

correlation = Correlation_Sender(correlation_mqtt)
machine = stmpy.Machine(name='Correlation', transitions=[t0, t1, t2, t3, t4, t5, t6],
                        obj=correlation, states=[idle, aggregation, correlation])
correlation.stm = machine


driver.add_machine(machine)
correlation_mqtt.start()
driver.start()