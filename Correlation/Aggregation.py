from datetime import timedelta, datetime
import json
import paho.mqtt.client as mqtt
from threading import Thread

def aggregation():
    #Parameters for the MQTT connection
    MQTT_BROKER = 'mosquitto'
    MQTT_PORT = 1883
    MQTT_USER = 'aggregation'
    MQTT_PASSWORD = 'aggregationPass'
    MQTT_TOPIC = 'detections/modules/#'
    MQTT_TOPIC_OUTPUT = 'detections/aggregation'

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
        mqtt_client.subscribe(MQTT_TOPIC)

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("Aggregation published to topic", MQTT_TOPIC)
    
    def on_message(client, userdata, msg):
        print('Incoming message to topic {}'.format(msg.topic))
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
            print(payload)
        except Exception as err:
            print('Message sent to topic {} had no valid JSON. Message ignored. {}'.format(msg.topic, err))
            return

        stime = payload.get('sTime')
        etime = payload.get('eTime')
        fuzzyStartTime = stime - timedelta(seconds = 30)
        gateway = payload.get('Gateway')
        attack_type = payload.get('Attack_type')
        exists = False
        existTime = datetime()
        for i in range(int((etime-fuzzyStartTime).total_seconds())+1):
            time = fuzzyStartTime + timedelta(seconds = i)
            if time.replace(microsecond=0) in alertDB[gateway]:
                exists = True
                existTime = time
        
        if exists:
            alertDB[gateway][existTime.replace(microsecond=0)].append(payload)
            if len(alertDB[gateway][existTime.replace(microsecond=0)]) > 3:
                mqtt_client.publish(MQTT_TOPIC_OUTPUT,json.dumps(alertDB))
        else:
            alertDB[gateway][etime.replace(microsecond=0)] = [payload]
        
      

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("aggregation")
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



