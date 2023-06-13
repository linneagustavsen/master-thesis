from datetime import datetime,timedelta
import os
from pathlib import Path
import numpy as np
from HelperFunctions.IsAttack import isAttack
from HelperFunctions.SimulateRealTime import simulateRealTime
from HelperFunctionsTelemetry.GetDataTelemetry import *
from HelperFunctions.GeneralizedEntropy import *
from HelperFunctions.Distributions import *
import json
import paho.mqtt.client as mqtt
from time import sleep
from random import randrange

from HelperFunctions.Normalization import normalization

'''
    Calculates entropy, packet and byte count and alerts in case of an anomaly
    Input:  start:                  string, indicating the start time of the data to detect on
            stop:                   string, indicating the stop time of the data to detect on
            systemId:               string, name of the system to collect and calculate on  
            if_name:                string, interface name, 
            interval:               timedelta object, size of the sliding window which the calculation is made on,
            frequency:              timedelta object, frequency of metric calculation,
            windowSize:             int, represents a multiplier of frequency, how far back we want to compare the value with
            thresholdEntropy:       float, values over this threshold will cause an alert
            thresholdEntropyRate:   float, values over this threshold will cause an alert
            attackDate:             string, date of the attack the calculations are made on
'''
def detectionEntropyTelemetry(start, stop, systemId, frequency, interval, windowSize, thresholdEntropy_ingress, thresholdEntropyRate_ingress, thresholdEntropy_egress, thresholdEntropyRate_egress, attackDate):

    json_file_ingress = open("Telemetry/Entropy/Calculations/MinMaxValues/MinMax.packet_size_ingress."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_ingress = json.load(json_file_ingress)
    json_file_rate_ingress = open("Telemetry/Entropy/Calculations/MinMaxValues/MinMax.packet_size_rate_ingress."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_rate_ingress = json.load(json_file_rate_ingress)

    json_file_egress = open("Telemetry/Entropy/Calculations/MinMaxValues/MinMax.packet_size_egress."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_egress = json.load(json_file_egress)
    json_file_rate_egress = open("Telemetry/Entropy/Calculations/MinMaxValues/MinMax.packet_size_rate_egress."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_rate_egress = json.load(json_file_rate_egress)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'entropyDetectionTelemetry'
    MQTT_PASSWORD = 'entropyDetectionPass'
    MQTT_TOPIC = 'detections/modules/telemetry'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        s=0
        #print(systemId, "Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print(systemId, "Entropy detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("EntropyDetectionTelemetry")
    #mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
    mqtt_client.loop_start()

    if attackDate == "08.03.23":
        fileString = "0803"
    elif attackDate == "17.03.23":
        fileString = "1703"
    elif attackDate == "24.03.23":
        fileString = "2403"
    data = pd.read_csv("Calculations"+fileString+"/Entropy/Telemetry/Metrics."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    sTime = pd.to_datetime(data["sTime"])
    eTime = pd.to_datetime(data["eTime"])
    real_label = data["real_label"]

    packetSizeArray_ingress = data["entropy_packet_size_ingress"]
    packetSizeRateArray_ingress = data["entropy_rate_packet_size_ingress"]
    if os.path.exists("Calculations"+fileString+"/Entropy/Telemetry/packetSizeDistributions_ingress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl"):
        packetSizeDistributionDict_ingress = pd.read_pickle("Calculations"+fileString+"/Entropy/Telemetry/packetSizeDistributions_ingress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")


    packetSizeArray_egress = data["entropy_packet_size_egress"]
    packetSizeRateArray_egress = data["entropy_rate_packet_size_egress"]
   
    truePositives_ingress = 0
    falsePositives_ingress = 0
    falseNegatives_ingress = 0
    trueNegatives_ingress  = 0

    truePositives_r_ingress = 0
    falsePositives_r_ingress = 0
    falseNegatives_r_ingress = 0
    trueNegatives_r_ingress  = 0


    truePositives_egress = 0
    falsePositives_egress = 0
    falseNegatives_egress = 0
    trueNegatives_egress  = 0

    truePositives_r_egress = 0
    falsePositives_r_egress = 0
    falseNegatives_r_egress = 0
    trueNegatives_r_egress  = 0

    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    #Loop through all the flow records in the input file
    for i in range(len(sTime)):
        sTime[i] = sTime[i].replace(tzinfo=None)
        eTime[i] = eTime[i].replace(tzinfo=None)
        if eTime[i] > stopTime + frequency:
            break
        if sTime[i] < startTime:
            continue

        attack = real_label[i]
        #If there is not enough stored values to compare with we skip the detection
        if i >= windowSize:
            
            change_ingress = packetSizeArray_ingress[i] - np.nanmean(packetSizeArray_ingress[i-windowSize: i-1])
            change_r_ingress = packetSizeRateArray_ingress[i] - np.nanmean(packetSizeRateArray_ingress[i-windowSize: i-1])

            change_egress = packetSizeArray_egress[i] - np.nanmean(packetSizeArray_egress[i-windowSize: i-1])
            change_r_egress = packetSizeRateArray_egress[i] - np.nanmean(packetSizeRateArray_egress[i-windowSize: i-1])

            if change_ingress < 0:
                attackType = "Same protocol"
            else:
                attackType = "Different protocols"

            if change_egress < 0:
                attackType = "Same protocol"
            else:
                attackType = "Different protocols"

            simulateRealTime(datetime.now(), eTime[i], attackDate)
            
            if abs(change_ingress) > thresholdEntropy_ingress:
                alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change_ingress), maxmin_ingress["minimum"], maxmin_ingress["maximum"]),
                    "Packet_size_distribution": packetSizeDistributionDict_ingress[eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")],
                    "Real_label": int(attack),
                    "Attack_type": attackType
                }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
            if abs(change_r_ingress) > thresholdEntropyRate_ingress:
                alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change_r_ingress), maxmin_rate_ingress["minimum"], maxmin_rate_ingress["maximum"]),
                    "Packet_size_distribution": packetSizeDistributionDict_ingress[eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")],
                    "Real_label": int(attack),
                    "Attack_type": attackType
                }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
            
            if abs(change_egress) > thresholdEntropy_egress:
                alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change_egress), maxmin_egress["minimum"], maxmin_egress["maximum"]),
                    "Real_label": int(attack),
                    "Attack_type": attackType
                }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
            if abs(change_r_egress) > thresholdEntropyRate_egress:
                alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change_r_egress), maxmin_rate_egress["minimum"], maxmin_rate_egress["maximum"]),
                    "Real_label": int(attack),
                    "Attack_type": attackType
                }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

            if abs(change_ingress) > thresholdEntropy_ingress and attack:
                truePositives_ingress += 1
            elif abs(change_ingress) > thresholdEntropy_ingress and not attack:
                falsePositives_ingress += 1
            elif abs(change_ingress) <= thresholdEntropy_ingress and attack:
                falseNegatives_ingress +=1
            elif abs(change_ingress) <= thresholdEntropy_ingress and not attack:
                trueNegatives_ingress += 1

            
            if abs(change_r_ingress) > thresholdEntropyRate_ingress and attack:
                truePositives_r_egress += 1
            elif abs(change_r_ingress) > thresholdEntropyRate_ingress and not attack:
                falsePositives_r_egress += 1
            elif abs(change_r_ingress) <= thresholdEntropyRate_ingress and attack:
                falseNegatives_r_egress += 1
            elif abs(change_r_ingress) <= thresholdEntropyRate_ingress and not attack:
                trueNegatives_r_egress += 1

            if abs(change_egress) > thresholdEntropy_egress and attack:
                truePositives_egress += 1
            elif abs(change_egress) > thresholdEntropy_egress and not attack:
                falsePositives_egress += 1
            elif abs(change_egress) <= thresholdEntropy_egress and attack:
                falseNegatives_egress +=1
            elif abs(change_egress) <= thresholdEntropy_egress and not attack:
                trueNegatives_egress += 1

            
            if abs(change_r_egress) > thresholdEntropyRate_egress and attack:
                truePositives_r_egress += 1
            elif abs(change_r_egress) > thresholdEntropyRate_egress and not attack:
                falsePositives_r_egress += 1
            elif abs(change_r_egress) <= thresholdEntropyRate_egress and attack:
                falseNegatives_r_egress += 1
            elif abs(change_r_egress) <= thresholdEntropyRate_egress and not attack:
                trueNegatives_r_egress += 1
        else:
            if attack:
               falseNegatives_ingress +=1
               falseNegatives_r_ingress += 1

               falseNegatives_egress +=1
               falseNegatives_r_egress += 1
            elif not attack:
                trueNegatives_ingress += 1
                trueNegatives_r_ingress += 1

                trueNegatives_egress += 1
                trueNegatives_r_egress += 1
            
            

    sleep(randrange(400))
    p = Path('Detections' + fileString)
    q = p / 'Entropy' / 'Telemetry'
    if not q.exists():
        q.mkdir(parents=True)

    #Open file to write alerts to
    scores_ingress = open(str(q) + "/Scores.EntropyPacketSize_ingress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    scores_r_ingress = open(str(q) + "/Scores.EntropyRatePacketSize_ingress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    scores_egress = open(str(q) + "/Scores.EntropyPacketSize_egress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    scores_r_egress = open(str(q) + "/Scores.EntropyRatePacketSize_egress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    scores_ingress.write("TP,FP,FN,TN")
    scores_r_ingress.write("TP,FP,FN,TN")
    scores_ingress.write("\n"+ str(truePositives_ingress)+ "," + str(falsePositives_ingress)+ "," + str(falseNegatives_ingress)+ "," + str(trueNegatives_ingress))
    scores_ingress.close()

    scores_r_ingress.write("\n"+ str(truePositives_r_ingress)+ "," + str(falsePositives_r_ingress)+ "," + str(falseNegatives_r_ingress)+ "," + str(trueNegatives_r_ingress))
    scores_r_ingress.close()

    scores_egress.write("TP,FP,FN,TN")
    scores_r_egress.write("TP,FP,FN,TN")
    scores_egress.write("\n"+ str(truePositives_egress)+ "," + str(falsePositives_egress)+ "," + str(falseNegatives_egress)+ "," + str(trueNegatives_egress))
    scores_egress.close()

    scores_r_egress.write("\n"+ str(truePositives_r_egress)+ "," + str(falsePositives_r_egress)+ "," + str(falseNegatives_r_egress)+ "," + str(trueNegatives_r_egress))
    scores_r_egress.close()
