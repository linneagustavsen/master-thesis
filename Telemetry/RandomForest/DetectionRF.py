import pandas as pd
import numpy as np
import json
import paho.mqtt.client as mqtt
import pickle
from HelperFunctions.IsAttack import isAttack

'''
    Detect anomalies based on a random forest classifier
    Input:  
            trainingSet:    pandas dataframe, training data set
            testingSet:     pandas dataframe, testing data set
            systemId:       string, name of the system to collect and calculate on  
            interval:       timedelta object, size of the sliding window which the calculation is made on
            attackDate:     string, date of the attack the calculations are made on
'''
def detectionRandomForestTelemetry(testingSet, systemId, interval, attackDate):
    f = open("Detections/RandomForest/Telemetry/Alerts."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_not = open("Detections/RandomForest/Telemetry/NotAlerts."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f.write("Time,egress_queue_info__0__avg_buffer_occupancy,egress_queue_info__0__cur_buffer_occupancy,egress_stats__if_1sec_pkts,egress_stats__if_1sec_octets,entropy_packet_size,entropy_rate_packet_size,real_label")
    f_not.write("Time,egress_queue_info__0__avg_buffer_occupancy,egress_queue_info__0__cur_buffer_occupancy,egress_stats__if_1sec_pkts,egress_stats__if_1sec_octets,entropy_packet_size,entropy_rate_packet_size,real_label")

    #Parameters for the MQTT connection
    MQTT_BROKER = 'mosquitto'
    MQTT_PORT = 1883
    MQTT_USER = 'randomForestDetectionTelemetry'
    MQTT_PASSWORD = 'randomForestDetectionPass'
    MQTT_TOPIC = 'detections/modules/telemetry'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client,userdata,result):
        print("Sensor data published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("RandomForestDetectionTelemetry")
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)

    # Load the model
    filename = "Telemetry/RandomForest/Models/RandomForestModel."+str(systemId)+ ".pkl"
    classifier_RF = pickle.load(open(filename, 'rb'))

    timeStamps = pd.read_pickle("Telemetry/RandomForest/RawData/Testing."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")["_time"].to_numpy()
    
    testingMeasurements = np.array(testingSet.iloc[:, 0:-1])
    testingLabel = np.array(testingSet.iloc[:,-1])

    #Predict the label of the testing data set
    predictions = classifier_RF.predict(testingMeasurements)
    for i in range(len(predictions)):
        if predictions[i] == 1:
            print("One alert at index:", i, "this had label", testingLabel[i], "in the testing data set")
            line = "\n"  + timeStamps[i].strftime("%Y-%m-%dT%H:%M:%SZ")
            for j in range(len(testingMeasurements[i])):
                line += "," + str(testingMeasurements[i][j])
            line += "," +str(testingLabel[i])
            f.write(line)
            alert = {
                    "Time": timeStamps[i],
                    "Gateway": systemId,
                    "Value": testingMeasurements[i],
                    "Real_label": testingLabel[i],
                    "Attack_type": "Flooding"
                }
            mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

    f.close()
    f_not.close()


'''trainingSet = "Telemetry/RandomForest/Data/TrainingSet.pkl"
testingSet = "Telemetry/RandomForest/Data/TestingSet.pkl"
systemId = "trd-gw"
interval = timedelta(minutes = 5)
attackDate = "21.09"
detectionRFTelemetry(trainingSet, testingSet, systemId, interval, attackDate)'''