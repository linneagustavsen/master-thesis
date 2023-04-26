from Correlation.CorrelationAttackTypes import Correlation_Attack_types
#Parameters for the MQTT connection
MQTT_BROKER = 'localhost'
MQTT_PORT = 1883
MQTT_USER = 'correlation'
MQTT_PASSWORD = 'correlationPass'
MQTT_TOPIC_INPUT = 'detections/aggregation/attackType'
MQTT_TOPIC_OUTPUT = 'detections/correlation'
correlation = Correlation_Attack_types(MQTT_BROKER, MQTT_PORT, MQTT_TOPIC_INPUT, MQTT_TOPIC_OUTPUT)
correlation.start()