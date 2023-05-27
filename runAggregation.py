
#Parameters for the MQTT connection
from Correlation.Aggregation import Aggregation
from Correlation.NetworkGraph import NetworkGraph


MQTT_BROKER = 'localhost'
MQTT_PORT = 1883
MQTT_USER = 'aggregation'
MQTT_PASSWORD = 'aggregationPass'
MQTT_TOPIC_INPUT = 'detections/modules/#'
MQTT_TOPIC_OUTPUT_TIME = 'detections/aggregation/time'
MQTT_TOPIC_OUTPUT_IPS = 'detections/aggregation/ips'
MQTT_TOPIC_OUTPUT_ATTACK_TYPE = 'detections/aggregation/attackType'
MQTT_TOPIC_OUTPUT_Distribution = 'detections/aggregation/distribution'


graph = NetworkGraph()
aggregation = Aggregation(MQTT_BROKER, MQTT_PORT, MQTT_TOPIC_INPUT, MQTT_TOPIC_OUTPUT_TIME, MQTT_TOPIC_OUTPUT_IPS, MQTT_TOPIC_OUTPUT_ATTACK_TYPE,MQTT_TOPIC_OUTPUT_Distribution, graph)
aggregation.start()
