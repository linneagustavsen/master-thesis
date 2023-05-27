from datetime import datetime,timedelta
from pathlib import Path
import numpy as np
from HelperFunctions.IsAttack import isAttack
from HelperFunctionsTelemetry.GetDataTelemetry import *
from HelperFunctions.GeneralizedEntropy import *
from HelperFunctions.Distributions import *
import json
import paho.mqtt.client as mqtt

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
def detectionEntropyTelemetry(start, stop, systemId, interval, frequency, windowSize, thresholdEntropy, thresholdEntropyRate, attackDate):
    p = Path('Detections')
    q = p / 'Entropy' / 'Telemetry'
    if not q.exists():
        q.mkdir(parents=True)

    #Open file to write alerts to
    TPf = open(str(q) + "/TP.EntropyPacketSize."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TPf_rate = open(str(q) + "/TP.EntropyRatePacketSize."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    TPf.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    TPf_rate.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open file to write alerts to
    FPf = open(str(q) + "/FP.EntropyPacketSize."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FPf_rate = open(str(q) + "/FP.EntropyRatePacketSize."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    FPf.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    FPf_rate.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open file to write alerts to
    FNf = open(str(q) + "/FN.EntropyPacketSize."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FNf_rate = open(str(q) + "/FN.EntropyRatePacketSize."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    FNf.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    FNf_rate.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open file to write alerts to
    TNf = open(str(q) + "/TN.EntropyPacketSize."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TNf_rate = open(str(q) + "/TN.EntropyRatePacketSize."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    TNf.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    TNf_rate.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    json_file = open("Telemetry/Entropy/Calculations/MinMaxValues/MinMax.packet_size."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin = json.load(json_file)
    json_file_rate = open("Telemetry/Entropy/Calculations/MinMaxValues/MinMax.packet_size_rate."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_rate = json.load(json_file_rate)
   
    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'entropyDetectionTelemetry'
    MQTT_PASSWORD = 'entropyDetectionPass'
    MQTT_TOPIC = 'detections/modules/telemetry'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("Entropy detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("EntropyDetectionTelemetry")
    #mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
    mqtt_client.loop_start()

    #Instantiate empty arrays for the calculated values
    packetSizeArray = []
    packetSizeRateArray = []

    #Makes datetime objects of the input times
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    intervalTime = (stopTime - startTime).total_seconds()/frequency.total_seconds()

    #Loop for every minute in a week
    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + interval
        #Get data for a specified time interval
        df = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),systemId, ["egress_stats__if_1sec_octets","egress_stats__if_1sec_pkts"])
        if df.empty:
            packetSizeArray.append(np.nan)
            packetSizeRateArray.append(np.nan)
            startTime = startTime + frequency
            continue
        dfEgressBytes = df["egress_stats__if_1sec_octets"].to_numpy()
        dfEgressPackets = df["egress_stats__if_1sec_pkts"].to_numpy()

        #If there is not enough datapoints the minute is skipped
        if len(dfEgressBytes) < 10 or len(dfEgressPackets) < 10:
            packetSizeArray.append(np.nan)
            packetSizeRateArray.append(np.nan)
            startTime = startTime + frequency
            continue

        #Find the probability distribution based on how big the packets are this time interval
        PiPS,nps,packetSizeDistributionDict = packetSizeDistributionDetection(dfEgressBytes, dfEgressPackets)
        #Calculate the generalized entropy of this distribution
        entropyPacketSize = generalizedEntropy(10, PiPS)
        packetSizeArray.append(entropyPacketSize)
        #Calculate the generalized entropy rate of this distribution
        packetSizeRateArray.append(entropyPacketSize/nps)

        #If there is not enough stored values to compare with we skip the detection
        if i < windowSize:
            #Push the start time by the specified frequency
            startTime = startTime + frequency
            continue
        attack = isAttack(stopTime- frequency, stopTime)
        #Compare the difference of each metric with a threshold
        if packetSizeArray !=  np.nan:
            change = packetSizeArray[i] - np.nanmean(packetSizeArray[i-windowSize: i-1])
            if change < 0:
                attackType = "Same protocol"
            else:
                attackType = "Different protocols"
            if abs(change) > thresholdEntropy:
                alert = {
                    "sTime": (stopTime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change), maxmin["minimum"], maxmin["maximum"]),
                    "Packet_size_distribution": packetSizeDistributionDict,
                    '''"Change": abs(change),
                    "Value": packetSizeArray[i],
                    "Mean_last_10": np.nanmean(packetSizeArray[i-windowSize: i-1]),'''
                    "Real_label": int(attack),
                    "Attack_type": attackType
                }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
            line = "\n" + (stopTime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  stopTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(normalization(abs(change), maxmin["minimum"], maxmin["maximum"])) + ","+ str(abs(change)) + "," + str(packetSizeArray[i]) + "," + str(np.nanmean(packetSizeArray[i-windowSize: i-1]))
            if abs(change) > thresholdEntropy and attack:
                TPf.write(line)
            elif abs(change) > thresholdEntropy and not attack:
                FPf.write(line)
            elif abs(change) <= thresholdEntropy and attack:
                FNf.write(line)
            elif abs(change) <= thresholdEntropy and not attack:
                TNf.write(line)
        else:
            line = "\n" + (stopTime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  stopTime.strftime("%Y-%m-%dT%H:%M:%SZ")
            if attack:
                FNf.write(line)
            elif not attack:
                TNf.write(line)
        if packetSizeRateArray !=  np.nan:
            change_r = packetSizeRateArray[i] - np.nanmean(packetSizeRateArray[i-windowSize: i-1])
            if abs(change_r) > thresholdEntropyRate:
                alert = {
                    "sTime": (stopTime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change_r), maxmin_rate["minimum"], maxmin_rate["maximum"]),
                    "Packet_size_distribution": packetSizeDistributionDict,
                    '''"Change": abs(change_r),
                    "Value": packetSizeRateArray[i],
                    "Mean_last_10": np.nanmean(packetSizeRateArray[i-windowSize: i-1]),'''
                    "Real_label": int(attack),
                    "Attack_type": attackType
                }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
            line = "\n" + (stopTime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  stopTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(normalization(abs(change_r), maxmin_rate["minimum"], maxmin_rate["maximum"])) + ","+ str(abs(change_r)) + "," + str(packetSizeRateArray[i]) + "," + str(np.nanmean(packetSizeRateArray[i-windowSize: i-1]))
            if abs(change) > thresholdEntropyRate and attack:
                TPf_rate.write(line)
            elif abs(change) > thresholdEntropyRate and not attack:
                FPf_rate.write(line)
            elif abs(change) <= thresholdEntropyRate and attack:
                FNf_rate.write(line)
            elif abs(change) <= thresholdEntropyRate and not attack:
                TNf_rate.write(line)
        else:
            line = "\n" + (stopTime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  stopTime.strftime("%Y-%m-%dT%H:%M:%SZ")
            if attack:
                FNf_rate.write(line)
            elif not attack:
                TNf_rate.write(line)
        #Push the start time by the specified frequency
        startTime = startTime + frequency

    TPf.close()
    FPf.close()
    FNf.close()
    TNf.close()
    TPf_rate.close()
    FPf_rate.close()
    FNf_rate.close()
    TNf_rate.close()
'''
start = "2022-09-21 01:00:00"
stop = "2022-09-22 00:00:00"
systemId = "trd-gw"
if_name = "xe-0/1/0"
interval = timedelta(minutes = 5)
frequency = timedelta(minutes = 1)
attackDate = "21.09"
windowSize = 10
thresholdEntropy = 0.5
thresholdEntropyRate = 0.005
thresholdPackets = 1000
thresholdBytes = 1000
detectionEntropyTelemetry(systemId, if_name, start, stop, frequency, interval, windowSize, thresholdEntropy, thresholdEntropyRate, thresholdPackets, thresholdBytes, attackDate)'''