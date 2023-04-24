from Correlation.CorrelationTime import Correlation_Time
from Correlation.NetworkGraph import NetworkGraph


#Parameters for the MQTT connection
MQTT_BROKER = 'localhost'
MQTT_PORT = 1883
MQTT_USER = 'correlation'
MQTT_PASSWORD = 'correlationPass'
MQTT_TOPIC_INPUT = 'detections/aggregation/time'
MQTT_TOPIC_OUTPUT = 'detections/correlation'
graph = NetworkGraph()
correlation = Correlation_Time(MQTT_BROKER, MQTT_PORT, MQTT_TOPIC_INPUT, MQTT_TOPIC_OUTPUT, graph)
correlation.start()