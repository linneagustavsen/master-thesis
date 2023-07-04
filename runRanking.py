
#Parameters for the MQTT connection
from Correlation.NetworkGraph import NetworkGraph
from Correlation.Ranking import Ranking
import sys
arguments = sys.argv


MQTT_BROKER = 'localhost'
MQTT_PORT = 1883
MQTT_USER = 'aggregation'
MQTT_PASSWORD = 'aggregationPass'
MQTT_TOPIC_INPUT = 'detections/correlation/#'
MQTT_TOPIC_OUTPUT = 'detections/ranking'


graph = NetworkGraph()
ranking = Ranking(MQTT_BROKER, MQTT_PORT, MQTT_TOPIC_INPUT, MQTT_TOPIC_OUTPUT, graph, arguments[1])
ranking.start()