from Correlation.CorrelationAttackTypes import Correlation_Attack_types
from Correlation.CorrelationDistribution import Correlation_Distribution
from Correlation.NetworkGraph import NetworkGraph

#Parameters for the MQTT connection
MQTT_BROKER = 'localhost'
MQTT_PORT = 1883
MQTT_USER = 'correlation'
MQTT_PASSWORD = 'correlationPass'
MQTT_TOPIC_INPUT = 'detections/aggregation/distribution'
MQTT_TOPIC_OUTPUT = 'detections/correlation'
graph = NetworkGraph()
correlation = Correlation_Distribution(MQTT_BROKER, MQTT_PORT, MQTT_TOPIC_INPUT, MQTT_TOPIC_OUTPUT, graph)
correlation.start()