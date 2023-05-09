from pathlib import Path
from silk import *
from datetime import datetime, timedelta
import numpy as np
import paho.mqtt.client as mqtt
import json
from HelperFunctions.IsAttack import isAttackFlow
from HelperFunctions.Normalization import normalization
from HelperFunctions.SimulateRealTime import simulateRealTime

'''
    Calculates the number of SYN syn in a flow and alerts in case of an anomaly
    Input:  silkFile:   string, file with flow records sorted on time
            start:      string, start time of detection 
            stop:       string, stop time of detection 
            systemId:   string, name of the system to calculate on
            windowSize: int, represents a multiplier of frequency, how far back we want to compare the value with
            threshold:  int, values over this threshold will cause an alert
            attackDate: string, date of the attack the calculations are made on
'''
def synDetection(silkFile, start, stop, systemId, windowSize, threshold, attackDate):
    p = Path('Detections')
    q = p / 'Threshold' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    #Open file to write alerts to
    TPsynFile = open(str(q) + "/TP.SYN.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    TPsynFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open file to write alerts to
    FPsynFile = open(str(q) + "/FP.SYN.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    FPsynFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open file to write alerts to
    FNsynFile = open(str(q) + "/FN.SYN.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    FNsynFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open file to write alerts to
    TNsynFile = open(str(q) + "/TN.SYN.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    TNsynFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    p = Path('NetFlow')
    q = p / 'Threshold' / 'Calculations'
    if not q.exists():
        q = Path('Threshold')
        q = q / 'Calculations'
    json_file_syn = open(str(q) + "/MinMax.syn.json", "r")
    maxmin_syn = json.load(json_file_syn)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'synDetectionNetFlow'
    MQTT_PASSWORD = 'synDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("SYN detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("SYNDetectionNetFlow")
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)

    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')

    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    synPacketsPerFlow = []
    
    #Instantiate variables
    i = 0

    #Loop through all the flow records
    for rec in infile:
        if rec.etime > stopTime:
            continue
        if rec.stime < startTime:
            continue
        synPacketsPerFlow.append(rec.packets)

        attack = isAttackFlow(rec.sip, rec.dip, rec.stime, rec.etime)
        #If there is enough stored values to compare with we compare the difference of the metric with a threshold
        if i >= windowSize:
            change = synPacketsPerFlow[i] - np.nanmean(synPacketsPerFlow[i-windowSize: i-1])
            
            simulateRealTime(datetime.now(), rec.etime, attackDate)
            if rec.packets >= threshold:
                alert = {
                        "sTime": rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": rec.etime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "Deviation_score": normalization(abs(change), maxmin_syn["minimum"], maxmin_syn["maximum"]),
                        "srcIP": int(rec.sip),
                        "dstIP": int(rec.dip),
                        "srcPort": rec.sport,
                        "dstPort": rec.dport,
                        "Protocol": rec.protocol,
                        '''"Change": abs(change),
                        "Value": synPacketsPerFlow[i],
                        "Mean_last_10": np.nanmean(synPacketsPerFlow[i-windowSize: i-1]),'''
                        "Real_label": int(attack),
                        "Attack_type": "SYN Flood"
                        }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
            
            line = "\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.etime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(normalization(abs(change), maxmin_syn["minimum"], maxmin_syn["maximum"])) + ","+ str(abs(change)) + "," + str(synPacketsPerFlow[i]) + "," + str(np.nanmean(synPacketsPerFlow[i-windowSize: i-1]))
            if abs(change) > threshold and attack:
                TPsynFile.write(line)
            elif abs(change) > threshold and not attack:
                FPsynFile.write(line)
            elif abs(change) <= threshold and attack:
                FNsynFile.write(line)
            elif abs(change) <= threshold and not attack:
                TNsynFile.write(line)
        else:
            line = "\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.etime.strftime("%Y-%m-%dT%H:%M:%SZ")
            if attack:
                FNsynFile.write(line)
            elif not attack:
                TNsynFile.write(line)
        i += 1
    
    TPsynFile.close()
    FPsynFile.close()
    FNsynFile.close()
    TNsynFile.close()
    infile.close()

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
silkFile = pathToRawFiles+systemId + "/tcp-syn-"+ baseFile
windowSize = 10
synDetection(silkFile, start, stop, systemId, windowSize, 2, attackDate)