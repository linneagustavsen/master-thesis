from datetime import datetime,timedelta
from pathlib import Path
import numpy as np
from HelperFunctions.GetData import *
from HelperFunctions.GeneralizedEntropy import *
from HelperFunctions.Distributions import *
from HelperFunctions.IsAttack import isAttack
import json
import paho.mqtt.client as mqtt

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
            thresholdBytes:         float, values over this threshold will cause an alert
            attackDate:             string, date of the attack the calculations are made on
'''

def detectionBytesTelemetry(start, stop, systemId, if_name, interval, frequency, windowSize, thresholdBytes, attackDate):
    p = Path('Detections')
    r = p / 'Threshold' / 'Telemetry'
    if not r.exists():
        r.mkdir(parents=True)
    #Open file to write alerts to
    TPf_bytes = open(str(r) + "TP.NumberOfBytes."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    TPf_bytes.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open file to write alerts to
    FPf_bytes = open(str(r) + "FP.NumberOfBytes."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    FPf_bytes.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open file to write alerts to
    FNf_bytes = open(str(r) + "FN.NumberOfBytes."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    FNf_bytes.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open file to write alerts to
    TNf_bytes = open(str(r) + "TN.NumberOfBytes."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    TNf_bytes.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    json_file = open("Telemetry/Threshold/Calculations/MinMax.bytes."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin = json.load(json_file)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'mosquitto'
    MQTT_PORT = 1883
    MQTT_USER = 'bytesDetectionTelemetry'
    MQTT_PASSWORD = 'bytesDetectionPass'
    MQTT_TOPIC = 'detections/modules/telemetry'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client,userdata,result):
        print("Bytes detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("BytesDetectionTelemetry")
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)

    #Instantiate empty arrays for the calculated values
    bytesArray = []

    #Makes datetime objects of the input times
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    intervalTime = (stopTime - startTime).total_seconds()/frequency.total_seconds()

    #Loop for every minute in a week
    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + interval
        #Get data for a specified time interval
        df = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),systemId, if_name, ["egress_stats__if_1sec_octets"])
        if df.empty:
            startTime = startTime + frequency
            bytesArray.append(np.nan)
            continue
        dfEgressBytes = df["egress_stats__if_1sec_octets"].to_numpy()

        #If there is not enough datapoints the minute is skipped
        if len(dfEgressBytes) < 10:
            startTime = startTime + frequency
            bytesArray.append(np.nan)
            continue

        bytesArray.append(sum(dfEgressBytes))

        #If there is not enough stored values to compare with we skip the detection
        if i < windowSize:
            #Push the start time by the specified frequency
            startTime = startTime + frequency
            continue
        
        attack = isAttack(stopTime- frequency, stopTime)
        #Compare the difference of each metric with a threshold
        if bytesArray !=  np.nan:
            change = bytesArray[i] - np.nanmean(bytesArray[i-windowSize: i-1])
            if abs(change) > thresholdBytes:
                alert = {
                    "sTime": (stopTime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change), maxmin["minimum"], maxmin["maximum"]),
                    "Change": abs(change),
                    "Value": bytesArray[i],
                    "Mean_last_10": np.nanmean(bytesArray[i-windowSize: i-1]),
                    "Real_label": int(attack),
                    "Attack_type": "Flooding"
                }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
            
            line = "\n" + (stopTime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  stopTime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(normalization(abs(change), maxmin["minimum"], maxmin["maximum"])) + ","+ str(abs(change)) + "," + str(bytesArray[i]) + "," + str(np.nanmean(bytesArray[i-windowSize: i-1]))
            if abs(change) > thresholdBytes and attack:
                TPf_bytes.write(line)
            elif abs(change) > thresholdBytes and not attack:
                FPf_bytes.write(line)
            elif abs(change) <= thresholdBytes and attack:
                FNf_bytes.write(line)
            elif abs(change) <= thresholdBytes and not attack:
                TNf_bytes.write(line)
        else:
            line = "\n" + (stopTime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  stopTime.strftime("%Y-%m-%dT%H:%M:%SZ")
            if attack:
                FNf_bytes.write(line)
            elif not attack:
                TNf_bytes.write(line)
        #Push the start time by the specified frequency
        startTime = startTime + frequency

    TPf_bytes.close()
    FPf_bytes.close()
    FNf_bytes.close()
    TNf_bytes.close()

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
thresholdBytes = 1000
detectionBytesTelemetry(systemId, if_name, start, stop, frequency, interval, windowSize, thresholdEntropy, thresholdEntropyRate, thresholdPackets, thresholdBytes, attackDate)'''