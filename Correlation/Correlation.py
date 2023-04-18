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
    MQTT_TOPIC_OUTPUT = 'detections/correlation'

    alertDB = {
        "Time": [{"Time": 0,
            "Gateway": 0,
            "Change": 0,
            "Value": 0,
            "Mean_last_10": 0,
            "Real_label": 0,
            "Attack_type": 0}]
    }

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))
        mqtt_client.subscribe(MQTT_TOPIC)

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

        time = payload.get('Time')
        gateway = payload.get('Gateway')
        attack_type = payload.get('Attack_type')
        if time.replace(second=0, microsecond=0) not in alertDB:
            alertDB[time.replace(second=0, microsecond=0)] = []
        alertDB[time.replace(second=0, microsecond=0)].append(payload)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("Correlation")
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.on_message = on_message
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
    mqtt_client.loop_start() 

    while True:
        for key, value in alertDB:
            print(key, value)
            for time in key:
                print(time)



