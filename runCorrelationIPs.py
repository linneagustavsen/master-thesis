from Correlation.CorrelationIPs import Correlation_IPs
import sys
arguments = sys.argv
#Parameters for the MQTT connection
MQTT_BROKER = 'localhost'
MQTT_PORT = 1883
MQTT_USER = 'correlation'
MQTT_PASSWORD = 'correlationPass'
MQTT_TOPIC_INPUT = 'detections/aggregation/ips'
MQTT_TOPIC_OUTPUT = 'detections/correlation'
correlation = Correlation_IPs(MQTT_BROKER, MQTT_PORT, MQTT_TOPIC_INPUT, MQTT_TOPIC_OUTPUT, arguments[1])
correlation.start()