from datetime import datetime,timedelta
from pathlib import Path
import numpy as np
from HelperFunctions.GetData import *
from HelperFunctions.GeneralizedEntropy import *
from HelperFunctions.Distributions import *
from HelperFunctions.IsAttack import isAttack
import json
import paho.mqtt.client as mqtt
from time import sleep
from random import randrange

from HelperFunctions.Normalization import normalization
from HelperFunctionsTelemetry.GetDataTelemetry import getData


'''
    Calculates entropy, packet and byte count and alerts in case of an anomaly
    Input:  start:                  string, indicating the start time of the data to detect on
            stop:                   string, indicating the stop time of the data to detect on
            systemId:               string, name of the system to collect and calculate on  
            if_name:                string, interface name, 
            interval:               timedelta object, size of the sliding window which the calculation is made on,
            frequency:              timedelta object, frequency of metric calculation,
            windowSize:             int, represents a multiplier of frequency, how far back we want to compare the value with
            thresholdPackets:       float, values over this threshold will cause an alert
            attackDate:             string, date of the attack the calculations are made on
'''
def detectionPacketsTelemetry(start, stop, systemId, interval, frequency, windowSize, thresholdPackets, attackDate):
    p = Path('Detections')
    r = p / 'Threshold' / 'Telemetry'
    if not r.exists():
        r.mkdir(parents=True)
    #Open file to write alerts to
    TPf_packets = open(str(r) + "TP.NumberOfPackets."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    TPf_packets.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open file to write alerts to
    FPf_packets = open(str(r) + "FP.NumberOfPackets."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    FPf_packets.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open file to write alerts to
    FNf_packets = open(str(r) + "FN.NumberOfPackets."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    FNf_packets.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open file to write alerts to
    TNf_packets = open(str(r) + "TN.NumberOfPackets."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    TNf_packets.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    
    json_file = open("Telemetry/Threshold/Calculations/MinMaxValues/MinMax.packets."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin = json.load(json_file)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'packetsDetectionTelemetry'
    MQTT_PASSWORD = 'packetsDetectionPass'
    MQTT_TOPIC = 'detections/modules/telemetry'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        s=0
        #print(systemId, "Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client,userdata,result):
        print("Packet detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("PacketsDetectionTelemetry")
    #mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
    mqtt_client.loop_start()

    #Instantiate empty arrays for the calculated values
    packetNumberArray = []

    #Makes datetime objects of the input times
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    intervalTime = (stopTime - startTime).total_seconds()/frequency.total_seconds()

    #Loop for every minute in a week
    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + interval
        #Get data for a specified time interval
        df = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),systemId, ["egress_stats__if_1sec_pkts"])
        if df.empty:
            packetNumberArray.append(np.nan)
            startTime = startTime + frequency
            continue
        dfEgressPackets = df["egress_stats__if_1sec_pkts"].to_numpy()

        #If there is not enough datapoints the minute is skipped
        if len(dfEgressPackets) < 10:
            packetNumberArray.append(np.nan)
            startTime = startTime + frequency
            continue

        #Store the number of packets and bytes this time interval
        packetNumberArray.append(sum(dfEgressPackets))

        #If there is not enough stored values to compare with we skip the detection
        if i < windowSize:
            #Push the start time by the specified frequency
            startTime = startTime + frequency
            continue
        
        attack = isAttack(stopTime- frequency, stopTime)
        #Compare the difference of each metric with a threshold
        if packetNumberArray !=  np.nan:
            change = packetNumberArray[i] - np.nanmean(packetNumberArray[i-windowSize: i-1])
            if abs(change) > thresholdPackets:
                alert = {
                    "sTime": (stopTime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change), maxmin["minimum"], maxmin["maximum"]),
                    '''"Change": abs(change),
                    "Value": packetNumberArray[i],
                    "Mean_last_10": np.nanmean(packetNumberArray[i-windowSize: i-1]),'''
                    "Real_label": int(attack),
                    "Attack_type": "Flooding"
                }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
            line = "\n" + (stopTime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  stopTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(normalization(abs(change), maxmin["minimum"], maxmin["maximum"])) + ","+ str(abs(change)) + "," + str(packetNumberArray[i]) + "," + str(np.nanmean(packetNumberArray[i-windowSize: i-1]))
            if abs(change) > thresholdPackets and attack:
                TPf_packets.write(line)
            elif abs(change) > thresholdPackets and not attack:
                FPf_packets.write(line)
            elif abs(change) <= thresholdPackets and attack:
                FNf_packets.write(line)
            elif abs(change) <= thresholdPackets and not attack:
                TNf_packets.write(line)
        else:
            line = "\n" + (stopTime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  stopTime.strftime("%Y-%m-%dT%H:%M:%SZ")
            if attack:
                FNf_packets.write(line)
            elif not attack:
                TNf_packets.write(line)
        #Push the start time by the specified frequency
        startTime = startTime + frequency

    TPf_packets.close()
    FPf_packets.close()
    FNf_packets.close()
    TNf_packets.close()

'''start = "2022-09-21 01:00:00"
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
thresholdPackets = 1000
detectionPacketsTelemetry(systemId, if_name, start, stop, frequency, interval, windowSize, thresholdEntropy, thresholdEntropyRate, thresholdPackets, thresholdPackets, attackDate)'''