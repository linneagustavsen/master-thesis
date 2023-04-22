from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import numpy as np
import paho.mqtt.client as mqtt
import json

'''
    Detect anomalies based on a random forest classifier and write them to file
    Input:  trainingSet:    pandas dataframe, training data set
            testingSet:     pandas dataframe, testing data set
            systemId:       string, name of the system to collect and detct on  
            interval:       timedelta object, size of the sliding window which the detection is made on
            attackDate:     string, date of the attack the detection are made on
'''
def detectionRandomForestNetFlow(trainingSet, testingSet, systemId, interval, attackDate):
    p = Path('Detections')
    q = p / 'RandomForest' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)

    TPf = open(str(q) + "/NetFlow/TP."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TPf.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,packet_size_entropy,packet_size_entropy_rate,real_label")

    FPf = open(str(q) + "/NetFlow/FP."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FPf.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,packet_size_entropy,packet_size_entropy_rate,real_label")

    FNf = open(str(q) + "/NetFlow/FN."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FNf.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,packet_size_entropy,packet_size_entropy_rate,real_label")

    TNf = open(str(q) + "/NetFlow/TN."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TNf.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,packet_size_entropy,packet_size_entropy_rate,real_label")
    #Parameters for the MQTT connection
    MQTT_BROKER = 'mosquitto'
    MQTT_PORT = 1883
    MQTT_USER = 'randomForestCombinedDetectionNetFlow'
    MQTT_PASSWORD = 'randomForestCombinedDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("Random forest combined detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("RandomForestCombinedDetectionNetFlow")
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)

    trainingMeasurements = np.array(trainingSet.iloc[:, 0:-1])
    trainingLabel = np.array(trainingSet.iloc[:,-1])

    classifier_RF = RandomForestClassifier(n_estimators = 100)
    classifier_RF.fit(trainingMeasurements,trainingLabel)

    p = Path('NetFlow')
    q = p / 'RandomForest' / 'RawData'
    if not q.exists():
        q.mkdir(parents=True)
    sTimes = pd.read_pickle(str(q) + "/Testing."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")["sTime"].to_numpy()
    eTimes = pd.read_pickle(str(q) + "/Testing."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")["eTime"].to_numpy()
    sTimes = pd.to_datetime(sTimes)
    eTimes = pd.to_datetime(eTimes)

    testingMeasurements = np.array(testingSet.iloc[:, 0:-1])
    testingLabel = np.array(testingSet.iloc[:,-1])

    predictions = classifier_RF.predict(testingMeasurements)
    for i in range(len(predictions)):
        if predictions[i] == 1:
            alert = {
                    "sTime": sTimes[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTimes[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "srcIP":testingMeasurements[i][0],
                    "dstIP": testingMeasurements[i][1],
                    "srcPort": testingMeasurements[i][2],
                    "dstPort": testingMeasurements[i][3],
                    "protocol": testingMeasurements[i][4],
                    "Value": testingMeasurements[i],
                    "Real_label": testingLabel[i],
                    "Attack_type": ""
                }
            mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

        line = "\n"  + sTimes[i].strftime("%Y-%m-%dT%H:%M:%SZ") + "," + eTimes[i].strftime("%Y-%m-%dT%H:%M:%SZ")
        for j in range(len(testingMeasurements[i])):
            #Skip IP fields
            if j == 0 or j == 1 or j == 16:
                continue
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
'''
    Detect anomalies based on a random forest classifier and write them to file
    Specifically without IPs
    Input:  trainingSet:    pandas dataframe, training data set
            testingSet:     pandas dataframe, testing data set
            systemId:       string, name of the system to collect and detect on  
            interval:       timedelta object, size of the sliding window which the detection is made on
            attackDate:     string, date of the attack the detections are made on
'''
def detectionRandomForestNoIPNetFlow(trainingSet, testingSet, systemId, interval, attackDate):
    p = Path('Detections')
    q = p / 'RandomForest' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    TPf = open(str(q) + "/NetFlow/TP.NoIP."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TPf.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,packet_size_entropy,packet_size_entropy_rate,real_label")

    FPf = open(str(q) + "/NetFlow/FP.NoIP."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FPf.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,packet_size_entropy,packet_size_entropy_rate,real_label")

    FNf = open(str(q) + "/NetFlow/FN.NoIP."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FNf.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,packet_size_entropy,packet_size_entropy_rate,real_label")

    TNf = open(str(q) + "/NetFlow/TN.NoIP."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TNf.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,packet_size_entropy,packet_size_entropy_rate,real_label")
    #Parameters for the MQTT connection
    MQTT_BROKER = 'mosquitto'
    MQTT_PORT = 1883
    MQTT_USER = 'randomForestCombinedNoIPDetectionNetFlow'
    MQTT_PASSWORD = 'randomForestCombinedNoIPDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("Random forest combined no IP detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("RandomForestCombinedNoIPDetectionNetFlow")
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)

    trainingMeasurements = np.array(trainingSet.iloc[:, 0:-1])

    trainingLabel = np.array(trainingSet.iloc[:,-1])

    classifier_RF = RandomForestClassifier(n_estimators = 100)
    classifier_RF.fit(trainingMeasurements,trainingLabel)

    p = Path('NetFlow')
    q = p / 'RandomForest' / 'RawData'
    if not q.exists():
        q.mkdir(parents=True)
    sTimes = pd.read_pickle(str(q) + "/NoIPTesting."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")["sTime"].to_numpy()
    eTimes = pd.read_pickle(str(q) + "/NoIPTesting."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")["eTime"].to_numpy()
    sTimes = pd.to_datetime(sTimes)
    eTimes = pd.to_datetime(eTimes)

    testingMeasurements = np.array(testingSet.iloc[:,  0:-1])
    testingLabel = np.array(testingSet.iloc[:,-1])

    predictions = classifier_RF.predict(testingMeasurements)
    for i in range(len(predictions)):
        if predictions[i] == 1:
            alert = {
                    "sTime": sTimes[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTimes[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "srcPort": testingMeasurements[i][0],
                    "dstPort": testingMeasurements[i][1],
                    "protocol": testingMeasurements[i][2],
                    "Value": testingMeasurements[i],
                    "Real_label": testingLabel[i],
                    "Attack_type": ""
                }
            mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

        line = "\n"  + sTimes[i].strftime("%Y-%m-%dT%H:%M:%SZ") + "," + eTimes[i].strftime("%Y-%m-%dT%H:%M:%SZ")
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