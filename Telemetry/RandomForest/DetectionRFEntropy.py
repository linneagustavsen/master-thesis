from datetime import timedelta
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import numpy as np
import json
import paho.mqtt.client as mqtt
import pickle

'''
    Detect anomalies based on a random forest classifier
    Input:  
            trainingSet:    pandas dataframe, training data set
            testingSet:     pandas dataframe, testing data set
            systemId:       string, name of the system to collect and calculate on  
            interval:       timedelta object, size of the sliding window which the calculation is made on
            attackDate:     string, date of the attack the calculations are made on
'''
def detectionRandomForestTelemetry(testingSet, systemId, interval, frequency, attackDate):
    p = Path('Detections')
    q = p / 'RandomForest' / 'Telemetry'
    if not q.exists():
        q.mkdir(parents=True)

    TPf = open(str(q) + "/Entropy.TP."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TPf.write("sTime,eTime,egress_queue_info__0__cur_buffer_occupancy,egress_stats__if_1sec_pkt,ingress_stats__if_1sec_pkt,egress_stats__if_1sec_octet,ingress_stats__if_1sec_octet,entropy_packet_size,entropy_rate_packet_size,real_label")
    
    FPf = open(str(q) + "/Entropy.FP."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FPf.write("sTime,eTime,egress_queue_info__0__cur_buffer_occupancy,egress_stats__if_1sec_pkt,ingress_stats__if_1sec_pkt,egress_stats__if_1sec_octet,ingress_stats__if_1sec_octet,entropy_packet_size,entropy_rate_packet_size,real_label")
    
    FNf = open(str(q) + "/Entropy.FN."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FNf.write("sTime,eTime,egress_queue_info__0__cur_buffer_occupancy,egress_stats__if_1sec_pkt,ingress_stats__if_1sec_pkt,egress_stats__if_1sec_octet,ingress_stats__if_1sec_octet,entropy_packet_size,entropy_rate_packet_size,real_label")
    
    TNf = open(str(q) + "/Entropy.TN."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TNf.write("sTime,eTime,egress_queue_info__0__cur_buffer_occupancy,egress_stats__if_1sec_pkt,ingress_stats__if_1sec_pkt,egress_stats__if_1sec_octet,ingress_stats__if_1sec_octet,entropy_packet_size,entropy_rate_packet_size,real_label")
    
    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'randomForestDetectionTelemetry'
    MQTT_PASSWORD = 'randomForestDetectionPass'
    MQTT_TOPIC = 'detections/modules/telemetry'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print(systemId, "Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client,userdata,result):
        s=0
        #print("Random Forest detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("RandomForestDetectionTelemetry")
    #mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
    mqtt_client.loop_start()

    p = Path('Telemetry')
    q = p / 'RandomForest'
    r = q / 'RawData'
    s = q / 'Models'
    if not q.exists():
        q.mkdir(parents=True)
    if not s.exists():
        s.mkdir(parents=True)
    # Load the model
    filename = str(s) + "/RandomForestModel.Entropy."+str(systemId)+ ".pkl"
    classifier_RF = pickle.load(open(filename, 'rb'))

    timeStamps = pd.read_pickle(str(r) + "/Entropy.Testing."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")["_time"].to_numpy()
    
    testingMeasurements = np.array(testingSet.iloc[:, 0:-1])
    testingLabel = np.array(testingSet.iloc[:,-1])

    #Predict the label of the testing data set
    predictions = classifier_RF.predict(testingMeasurements)
    for i in range(len(predictions)):
        if predictions[i] == 1:
            alert = {
                    "sTime": (timeStamps[i] - frequency).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": timeStamps[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": None,
                    #"Value": testingMeasurements[i],
                    "Real_label": testingLabel[i],
                    "Attack_type": "Flooding"
                }
            mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
        line = "\n" + (timeStamps[i] - frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeStamps[i].strftime("%Y-%m-%dT%H:%M:%SZ")
        for j in range(len(testingMeasurements[i])):
            line += "," + str(testingMeasurements[i][j])
        line += "," +str(testingLabel[i])

        if predictions[i] == 1 and testingLabel[i]:
            TPf.write(line)
        elif predictions[i] == 1 and not testingLabel[i]:
            FPf.write(line)
        elif predictions[i] == 0 and testingLabel[i]:
            FNf.write(line)
        elif predictions[i] == 0 and not testingLabel[i]:
            TNf.write(line)
    TPf.close()
    FPf.close()
    FNf.close()
    TNf.close()


'''trainingSet = "Telemetry/RandomForest/Data/TrainingSet.pkl"
testingSet = "Telemetry/RandomForest/Data/TestingSet.pkl"
systemId = "trd-gw"
interval = timedelta(minutes = 5)
attackDate = "21.09"
detectionRFTelemetry(trainingSet, testingSet, systemId, interval, attackDate)'''