from datetime import timedelta, datetime
import json
import paho.mqtt.client as mqtt
from threading import Thread

def correlation():
    #Parameters for the MQTT connection
    MQTT_BROKER = 'mosquitto'
    MQTT_PORT = 1883
    MQTT_USER = 'correlation'
    MQTT_PASSWORD = 'correlationPass'
    MQTT_TOPIC = 'detections/modules/#'
    MQTT_TOPIC_INPUT = 'detections/aggregation'
    MQTT_TOPIC_OUTPUT = 'detections/correlation'

    alertDB = {
        "Gateway": {
            "Time": [{"Time": 0,
                "Gateway": 0,
                "Change": 0,
                "Value": 0,
                "Mean_last_10": 0,
                "Real_label": 0,
                "Attack_type": 0}]
            }
    }

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))
        mqtt_client.subscribe(MQTT_TOPIC_INPUT)

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("Correlation published to topic", MQTT_TOPIC)
    
    def on_message(client, userdata, msg):
        print('Incoming message to topic {}'.format(msg.topic))
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
            print(payload)
        except Exception as err:
            print('Message sent to topic {} had no valid JSON. Message ignored. {}'.format(msg.topic, err))
            return

        for gateway, timestamps in payload:
            #If gateway1 is close to gateway2 and they have the same fuzzy timestamps
                #look at attack types
                #(look at IPs, ports, protocol)
                #If they are the same
                    #generate an alert for that time, that attack type, and the highest deviation score (or the mean)
                    #send the alert to the alert ranking
                    i = 0
        
        
      

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("correlation")
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.on_message = on_message
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
    mqtt_client.loop_start() 





