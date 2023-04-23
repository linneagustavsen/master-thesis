from Correlation.NetworkGraph import NetworkGraph
from Correlation.statemachine import Correlation_Sender, CorrelationStateMachineConfig
import stmpy
import paho.mqtt.client as mqtt
from threading import Thread
import json

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
    def __init__(self, broker, port, driver, inputTopic, outputTopic, graph):
        self.driver = driver
        self.port = port
        self.broker = broker
        self.input = inputTopic
        self.output = outputTopic
        self.graph = graph
        self.alert = 0

        self.alertsIP ={}

        self.alertsCorrelated = {}
    
    def addMachine(self):
        correlation = Correlation_Sender(self, self.alert)
        machine = stmpy.Machine(name=self.alert, transitions=CorrelationStateMachineConfig["transitions"],
                                obj=correlation, states=CorrelationStateMachineConfig["states"])
        correlation.stm = machine
        driver.add_machine(machine)
        self.alert += 1
        return correlation

    def addAlertsIP(self, ip, time, alert):
        self.alertsIP[ip] = {time.replace(microsecond=0):[alert]}

    def addTimestampAndAlertToAlertsIP(self, ip, time, alert):
        self.alertsIP[ip][time.replace(microsecond=0)] = [alert]

    def getAlertsIP(self, ip, time):
        return self.alertsIP[ip][time.replace(microsecond=0)]
    
    def getAlertsIP(self, ip):
        return self.alertsIP[ip]
    
    def addAlertToExistingTimestampAlertsIP(self, ip, time, alert):
        self.alertsIP[ip][time.replace(microsecond=0)].append(alert)
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

        self.addMachine(self)
        self.driver.send('aggregateTime',self.alert, args=[stime, etime, gateway, payload])
        
        try:
            srcIP = payload.get('srcIP')
            dstIP = payload.get('dstIP')

            self.addMachine(self)
            self.driver.send('aggregateIPs',self.alert, args=[stime, etime, srcIP, payload])

            self.addMachine(self)
            self.driver.send('aggregateIPs',self.alert, args=[stime, etime, dstIP, payload])

        except Exception as err:
            print('Message sent to topic {} had no IP addresses. {}'.format(msg.topic, err))
            return

    def start(self):
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_message = self.on_message
        self.mqtt_client.on_connect = self.on_connect
        
        self.mqtt_client.connect(self.broker, self.port)
        driver.start()
        try:
            thread = Thread(target=self.mqtt_client.loop_forever)
            thread.start()
            
        except KeyboardInterrupt:
            print("Interrupted")
            self.mqtt_client.disconnect()

graph = NetworkGraph()
driver = stmpy.Driver()
correlation_mqtt = Correlation_MQTT(MQTT_BROKER, MQTT_PORT, driver, MQTT_TOPIC_INPUT, MQTT_TOPIC_OUTPUT, graph)
correlation_mqtt.start()