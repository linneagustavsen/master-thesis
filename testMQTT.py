import json
import paho.mqtt.client as mqtt

#Parameters for the MQTT connection
MQTT_BROKER = 'mosquitto'
MQTT_PORT = 1883
MQTT_USER = 'SYNDetection'
MQTT_PASSWORD = 'synpass'
MQTT_TOPIC = 'detections/#'
MQTT_TOPIC_Detections = 'detections/modules'

#Function that is called when the sensor is connected to the MQTT broker
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))

#Function that is called when the sensor publish something to a MQTT topic
def on_publish(client,userdata,result):
    print("Sensor data published to topic", MQTT_TOPIC_Detections)

#Connects to the MQTT broker with password and username
mqtt_client = mqtt.Client("SynDetection")
mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
mqtt_client.on_publish = on_publish
mqtt_client.on_connect = on_connect
mqtt_client.connect(MQTT_BROKER, MQTT_PORT)

alert = {
    "Time": 0,
    "Change": 0,
    "Value": 0,
    "Mean_last_10": 0,
    "Attack_type": 0

}
mqtt_client.publish(MQTT_TOPIC_Detections,json.dumps(alert))
