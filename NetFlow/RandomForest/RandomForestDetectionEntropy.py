from datetime import timedelta,datetime
from pathlib import Path
import pickle
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import numpy as np
import paho.mqtt.client as mqtt
import json

from HelperFunctions.SimulateRealTime import simulateRealTime

'''
    Detect anomalies based on a random forest classifier and write them to file
    Input:  trainingSet:    pandas dataframe, training data set
            testingSet:     pandas dataframe, testing data set
            systemId:       string, name of the system to collect and detct on  
            interval:       timedelta object, size of the sliding window which the detection is made on
            attackDate:     string, date of the attack the detection are made on
'''
def detectionRandomForestNetFlowEntropy(testingSet, systemId, frequency, interval, attackDate):
    p = Path('Detections')
    q = p / 'RandomForest' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)

    TPf = open(str(q) + "/TP.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TPf.write("sTime,eTime,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets,packet_size_entropy,packet_size_entropy_rate,number_of_packets,number_of_bytes,real_label")

    FPf = open(str(q) + "/FP.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FPf.write("sTime,eTime,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets,packet_size_entropy,packet_size_entropy_rate,number_of_packets,number_of_bytes,real_label")

    FNf = open(str(q) + "/FN.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FNf.write("sTime,eTime,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets,packet_size_entropy,packet_size_entropy_rate,number_of_packets,number_of_bytes,real_label")

    TNf = open(str(q) + "/TN.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TNf.write("sTime,eTime,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets,packet_size_entropy,packet_size_entropy_rate,number_of_packets,number_of_bytes,real_label")

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'randomForestEntropyDetectionNetFlow'
    MQTT_PASSWORD = 'randomForestEntropyDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print(systemId, "Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("Random forest entropy detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("RandomForestEntropyDetectionNetFlow")
    #mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
    mqtt_client.loop_start()

    p = Path('NetFlow')
    q = p / 'RandomForest'
    r = q / 'RawData'
    s = q / 'Models'
    if not r.exists():
        q = Path('RandomForest')
        r = q / 'RawData'
    if not s.exists():
        q = Path('RandomForest')
        s= q / 'Models'
        
    # Load the model
    filename = str(s) + "/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl"
    classifier_RF = pickle.load(open(filename, 'rb'))

    timeStamps = pd.read_pickle(str(r) + "/Testing.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")["time"].to_numpy()
    timeStamps = pd.to_datetime(timeStamps)

    testingMeasurements = np.array(testingSet.iloc[:, 0:-1])
    testingLabel = np.array(testingSet.iloc[:,-1])

    predictions = classifier_RF.predict(testingMeasurements)
    for i in range(len(predictions)):
        #simulateRealTime(datetime.now(), timeStamps[i], attackDate)
        if predictions[i] == 1:
            alert = {
                    "sTime": (timeStamps[i]- frequency).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": timeStamps[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": None,
                    '''"Value": testingMeasurements[i].tolist(),
                    "Real_label": testingLabel[i],'''
                    "Attack_type": ""
                }
            mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

        line = "\n"  + (timeStamps[i]- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeStamps[i].strftime("%Y-%m-%dT%H:%M:%SZ")
        for j in range(len(testingMeasurements[i])):
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

baseFile="two-hours-2011-02-08_10-12-sorted.rw"         
systemId = "oslo-gw1"
start = "2011-02-08 10:00:00"
stop = "2011-02-08 12:00:00"
startCombined = "2011-02-08 10:00:00"
stopCombined = "2011-02-08 12:00:00"
frequency = timedelta(minutes = 1)
interval = timedelta(minutes = 10)
pathToRawFiles="/home/linneafg/silk-data/RawDataFromFilter/"
attackDate="08.02.11"
silkFile = pathToRawFiles+systemId + "/"+ baseFile
windowSize = 10

p = Path('NetFlow')
q = p / 'RandomForest' / 'DataSets'
if not q.exists():
    q = Path('RandomForest')
    q = q / 'DataSets'
testingPath = q / 'Testing'


testingSet= pd.read_pickle(str(testingPath) + "/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")

detectionRandomForestNetFlowEntropy(testingSet, systemId, frequency, interval, attackDate)