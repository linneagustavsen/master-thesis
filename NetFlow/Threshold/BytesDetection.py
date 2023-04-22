from pathlib import Path
from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime,timedelta
import numpy as np
import paho.mqtt.client as mqtt
import json
from HelperFunctions.IsAttack import isAttack
from HelperFunctions.Normalization import normalization

'''
    Calculates entropy and other metrics and alerts in case of an anomaly
    Input:  silkFile:                       string, file with flow records sorted on time
            start:                          string, indicating the start time of the data wanted
            stop:                           string, indicating the stop time of the data wanted
            systemId:                       string, name of the system to collect and calculate on
            frequency:                      timedelta object, frequency of metric calculation
            interval:                       timedelta object, size of the sliding window which the calculation is made on
            windowSize:                     int, represents a multiplier of frequency, how far back we want to compare the value with
            thresholdBytes:                 float, values over this threshold will cause an alert
            attackDate:                     string, date of the attack the calculations are made on
'''
def detectionBytesNetFlow(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdBytes, attackDate):
    p = Path('Detections')
    q = p / 'Threshold' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    #Open file to write alerts to
    TPbytesFile = open(str(q) + "/TP.Bytes."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    TPbytesFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open file to write alerts to
    FPbytesFile = open(str(q) + "/FP.Bytes."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    FPbytesFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open file to write alerts to
    FNbytesFile = open(str(q) + "/FN.Bytes."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    FNbytesFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open file to write alerts to
    TNbytesFile = open(str(q) + "/TN.Bytes."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    TNbytesFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    json_file_bytes = open("NetFlow/Threshold/Calculations/MinMax.bytes."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_bytes = json.load(json_file_bytes)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'mosquitto'
    MQTT_PORT = 1883
    MQTT_USER = 'bytesDetectionNetFlow'
    MQTT_PASSWORD = 'bytesDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("Bytes detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("BytesDetectionNetFlow")
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
    
    bytesArray = []
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
            lastSizes  = sum(sizes)
            thisMinuteSize = len(records) - lastSizes
            sizes.append(thisMinuteSize)
            windowTime += frequency
        #Aggregate flows into the specified time interval
        if rec.stime > startTime + interval:
            bytesArray.append(numberOfBytes(records))
            
            attack = isAttack(rec.stime - frequency, rec.stime)
            #If there is enough stored values to compare with we compare the difference of each metric with a threshold
            if i >=windowSize:
                change = bytesArray[i] - np.nanmean(bytesArray[i-windowSize: i-1])
                
                if abs(change) > thresholdBytes:
                    alert = {
                        "sTime": (rec.stime - frequency).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "Deviation_score": normalization(abs(change), maxmin_bytes["minimum"], maxmin_bytes["maximum"]),
                        "Change": abs(change),
                        "Value": bytesArray[i],
                        "Mean_last_10": np.nanmean(bytesArray[i-windowSize: i-1]),
                        "Real_label": int(attack),
                        "Attack_type": "Flooding"
                        }
                    mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
                
                line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(normalization(abs(change), maxmin_bytes["minimum"], maxmin_bytes["maximum"])) + ","+ str(abs(change)) + "," + str(bytesArray[i]) + "," + str(np.nanmean(bytesArray[i-windowSize: i-1]))
                if abs(change) > thresholdBytes and attack:
                    TPbytesFile.write(line)
                elif abs(change) > thresholdBytes and not attack:
                    FPbytesFile.write(line)
                elif abs(change) <= thresholdBytes and attack:
                    FNbytesFile.write(line)
                elif abs(change) <= thresholdBytes and not attack:
                    TNbytesFile.write(line)
            else:
                line = "\n" + (rec.stime - frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ")
                if attack:
                    FNbytesFile.write(line)
                elif not attack:
                    TNbytesFile.write(line)
            #Push the sliding window
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1

        records.append(rec)
    
    TPbytesFile.close()
    FPbytesFile.close()
    FNbytesFile.close()
    TNbytesFile.close()

    infile.close()
    