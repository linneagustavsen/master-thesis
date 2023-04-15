from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime,timedelta
import numpy as np
import paho.mqtt.client as mqtt
import json
from HelperFunctions.IsAttack import isAttack

'''
    Calculates entropy and other metrics and alerts in case of an anomaly
    Input:  silkFile:                       string, file with flow records sorted on time
            start:                          string, indicating the start time of the data wanted
            stop:                           string, indicating the stop time of the data wanted
            systemId:                       string, name of the system to collect and calculate on
            frequency:                      timedelta object, frequency of metric calculation
            interval:                       timedelta object, size of the sliding window which the calculation is made on
            windowSize:                     int, represents a multiplier of frequency, how far back we want to compare the value with
            thresholdICMPRatio:             float, values over this threshold will cause an alert
            thresholdNumberOfICMPPackets:   int, values over this threshold will cause an alert
            attackDate:                     string, date of the attack the calculations are made on
'''
def detectionICMP(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdICMPRatio, thresholdNumberOfICMPPackets, attackDate):
    #Open file to write alerts to
    icmpRatioFile = open("Detections/Threshold/NetFlow/ICMPRatio."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    icmpPacketsFile = open("Detections/Threshold/NetFlow/ICMPPackets."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    
    #Write the column titles to the files
    icmpRatioFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    icmpPacketsFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))

    #Parameters for the MQTT connection
    MQTT_BROKER = 'mosquitto'
    MQTT_PORT = 1883
    MQTT_USER = 'icmpDetectionNetFlow'
    MQTT_PASSWORD = 'icmpDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("Sensor data published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("ICMPDetectionNetFlow")
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
    
    #Makes datetime objects of the input times
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    windowTime = startTime

    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    records = []

    icmpRatioArray = []
    icmpPacketsArray = []

    #Instantiate variables
    i = 0
    sizes = []

    #Loop through all the flow records in the input file
    for rec in infile:
        if rec.etime >= stopTime:
            break
        if rec.stime < startTime:
            continue
        #Implement the sliding window
        if rec.stime > windowTime + frequency:
            lastSizes = 0
            for size in sizes:
                lastSizes += size
            thisMinuteSize = len(records) - lastSizes
            sizes.append(thisMinuteSize)
            windowTime += frequency
        #Aggregate flows into the specified time interval
        if rec.stime > startTime + interval:
            #Find the ratio of ICMP packets in this time interval
            icmpRatio, icmpPackets = icmpDistribution(records)
            icmpRatioArray.append(icmpRatio)
            icmpPacketsArray.append(icmpPackets)
            
            #If there is enough stored values to compare with we compare the difference of each metric with a threshold
            if i >=windowSize:
                if abs(icmpRatioArray[i] - np.nanmean(icmpRatioArray[i-windowSize: i-1])) > thresholdICMPRatio:
                    icmpRatioFile.write("\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(icmpRatioArray[i] - np.nanmean(icmpRatioArray[i-windowSize: i-1]))) + "," + str(icmpRatioArray[i]) + "," + str(np.nanmean(icmpRatioArray[i-windowSize: i-1])))
                    alert = {
                        "Time": rec.stime,
                        "Gateway": systemId,
                        "Change": abs(icmpRatioArray[i] - np.nanmean(icmpRatioArray[i-windowSize: i-1])),
                        "Value": icmpRatioArray[i],
                        "Mean_last_10": np.nanmean(icmpRatioArray[i-windowSize: i-1]),
                        "Real_label": int(isAttack(rec.stime)),
                        "Attack_type": "ICMP Flood"
                        }
                    mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

                if abs(icmpPacketsArray[i] - np.nanmean(icmpPacketsArray[i-windowSize: i-1])) > thresholdNumberOfICMPPackets:
                    icmpPacketsFile.write("\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(icmpPacketsArray[i] - np.nanmean(icmpPacketsArray[i-windowSize: i-1]))) + "," + str(icmpPacketsArray[i]) + "," + str(np.nanmean(icmpPacketsArray[i-windowSize: i-1])))
                    alert = {
                        "Time": rec.stime,
                        "Gateway": systemId,
                        "Change": abs(icmpPacketsArray[i] - np.nanmean(icmpPacketsArray[i-windowSize: i-1])),
                        "Value": icmpPacketsArray[i],
                        "Mean_last_10": np.nanmean(icmpPacketsArray[i-windowSize: i-1]),
                        "Real_label": int(isAttack(rec.stime)),
                        "Attack_type": "ICMP Flood"
                        }
                    mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

            #Push the sliding window
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1

        records.append(rec)
    
    icmpRatioFile.close()
    icmpPacketsFile.close()

    infile.close()
    