from datetime import timedelta, datetime
import json
import paho.mqtt.client as mqtt
import networkx as nx

def aggregation():
    #Parameters for the MQTT connection
    MQTT_BROKER = 'mosquitto'
    MQTT_PORT = 1883
    MQTT_USER = 'aggregation'
    MQTT_PASSWORD = 'aggregationPass'
    MQTT_TOPIC = 'detections/modules/#'
    MQTT_TOPIC_OUTPUT = 'detections/aggregation'

    alertDB = {
            "Time": [{"Time": 0,
                "Gateway": 0,
                "Change": 0,
                "Value": 0,
                "Mean_last_10": 0,
                "Real_label": 0,
                "Attack_type": 0}]
            }
    

    G = nx.Graph()
    G.add_nodes_from(["bergen-gw3", "bergen-gw4", "hoytek-gw2", "hovedbygget-gw", "trd-gw", "teknobyen-gw2", "teknobyen-gw1", "ifi2-gw5", "ifi2-gw", 
                "oslo-gw1", "tromso-gw5", "stangnes-gw", "rodbergvn-gw2", "narvik-kv-gw", "narvik-gw3", "tromso-fh-gw",
                "ma2-gw", "narvik-gw4", "tullin-gw2", "tullin-gw1"])
    G.add_edges_from([("trd-gw", "rodbergvn-gw2"),("narvik-kv-gw","trd-gw"), ("trd-gw", "teknobyen-gw2"), ("trd-gw", "oslo-gw1"), ("trd-gw", "hovedbygget-gw"),
                  ("teknobyen-gw2", "teknobyen-gw1"), ("teknobyen-gw2","ifi2-gw5"), ("narvik-kv-gw", "teknobyen-gw2"), ("narvik-kv-gw", "ifi2-gw5"), ("narvik-kv-gw", "stangnes-gw"),
                  ("narvik-kv-gw", "tromso-fh-gw"), ("narvik-kv-gw", "narvik-gw3"), ("narvik-kv-gw", "narvik-gw4"), ("tromso-fh-gw",  "ma2-gw"), ("tromso-fh-gw", "tromso-gw5"),
                  ("ma2-gw", "tromso-gw5"), ("ma2-gw","narvik-gw3"), ("ma2-gw", "narvik-gw4"), ("narvik-gw3", "narvik-gw4"), ("narvik-gw3", "hovedbygget-gw"), 
                  ("hovedbygget-gw", "tullin-gw2"), ("hovedbygget-gw", "hoytek-gw2"),("ifi2-gw5", "oslo-gw1"), ("ifi2-gw5", "ifi2-gw"), ("ifi2-gw", "bergen-gw4"),
                  ("ifi2-gw", "tullin-gw1"), ("ifi2-gw", "oslo-gw1"), ("oslo-gw1", "tullin-gw1"), ("tullin-gw1", "tullin-gw2"), ("tullin-gw2", "hoytek-gw2"),
                  ("tullin-gw1", "bergen-gw3"), ("rodbergvn-gw2", "stangnes-gw"), ("bergen-gw3", "bergen-gw4"), ("bergen-gw3", "hoytek-gw2"), ("narvik-kv-gw", "ifi2-gw"),
                  ("oslo-gw1", "narvik-kv-gw")])
    
    for node in G:
        G.nodes[node]['alerts'] = {}
    
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
            if time.replace(microsecond=0) in G.nodes[gateway]['alerts']:
                exists = True
                existTime = time
        
        if exists:
            G.nodes[gateway]['alerts'][existTime.replace(microsecond=0)].append(payload)
            if len(G.nodes[gateway]['alerts'][existTime.replace(microsecond=0)]) > 3:
                mqtt_client.publish(MQTT_TOPIC_OUTPUT,json.dumps(G))
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



