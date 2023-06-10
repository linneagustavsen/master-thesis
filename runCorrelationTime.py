from Correlation.CorrelationTime import Correlation_Time
from Correlation.NetworkGraph import NetworkGraph
import sys
arguments = sys.argv


#Parameters for the MQTT connection
MQTT_BROKER = 'localhost'
MQTT_PORT = 1883
MQTT_USER = 'correlation'
MQTT_PASSWORD = 'correlationPass'
MQTT_TOPIC_INPUT = 'detections/aggregation/time'
MQTT_TOPIC_OUTPUT = 'detections/correlation/time'
graph = NetworkGraph()
correlation = Correlation_Time(MQTT_BROKER, MQTT_PORT, MQTT_TOPIC_INPUT, MQTT_TOPIC_OUTPUT, graph, arguments[1])
correlation.start()