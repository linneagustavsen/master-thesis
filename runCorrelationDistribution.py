from Correlation.CorrelationDistribution import Correlation_Distribution
from Correlation.NetworkGraph import NetworkGraph
import sys
arguments = sys.argv
#Parameters for the MQTT connection
MQTT_BROKER = 'localhost'
MQTT_PORT = 1883
MQTT_USER = 'correlation'
MQTT_PASSWORD = 'correlationPass'
MQTT_TOPIC_INPUT = 'detections/aggregation/distribution'
MQTT_TOPIC_OUTPUT = 'detections/correlation'
graph = NetworkGraph()
correlation = Correlation_Distribution(MQTT_BROKER, MQTT_PORT, MQTT_TOPIC_INPUT, MQTT_TOPIC_OUTPUT, graph, arguments[1])
correlation.start()