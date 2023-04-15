from silk import *
from HelperFunctions.Distributions import *
from datetime import datetime,timedelta
import numpy as np
import paho.mqtt.client as mqtt
import json
from HelperFunctions.IsAttack import isAttack

'''
    Calculates the number of ICMP destination unreachable packets in a flow and alerts in case of an anomaly
    Input:  silkFile:   string, file with flow records sorted on time
            start:      string, start time of detection 
            stop:       string, stop time of detection 
            systemId:   string, name of the system to calculate on
            frequency:  timedelta object, frequency of metric calculation
            interval:   timedelta object, size of the sliding window which the calculation is made on
            windowSize: int, represents a multiplier of frequency, how far back we want to compare the value with
            threshold:  int, values over this threshold will cause an alert
            attackDate: string, date of the attack the calculations are made on
'''
def icmpDstUnreachableDetection(silkFile, start, stop, systemId, frequency, interval, windowSize, threshold, attackDate):
    #Open file to write alerts to
    f = open("Detections/Threshold/NetFlow/ICMPDstUnreachable."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #Write the column titles to the files
    f.write("Time,Change,Value,Mean_last_"+ str(windowSize))

    #Parameters for the MQTT connection
    MQTT_BROKER = 'mosquitto'
    MQTT_PORT = 1883
    MQTT_USER = 'icmpDstUnreachableDetectionNetFlow'
    MQTT_PASSWORD = 'icmpDstUnreachableDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("Sensor data published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("ICMPDstUnreachableNetFlow")
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
    
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    windowTime = startTime
    
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)
    
    #Instantiate empty arrays for the calculated values
    records = []

    numberOfIcmpDstUnreachablePackets = []

    #Instantiate variables
    i = 0
    sizes = []
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
        if rec.stime > startTime + interval:
            #Find the number of ICMP Destination unavailable packets in this time interval
            numberOfIcmpDstUnreachablePackets.append(numberOfPackets(records))
            
            #If there is enough stored values to compare with we compare the difference of the metric with a threshold
            if i >= windowSize:
                if abs(numberOfIcmpDstUnreachablePackets[i] - np.nanmean(numberOfIcmpDstUnreachablePackets[i-windowSize: i-1])) > threshold:
                    f.write("\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(numberOfIcmpDstUnreachablePackets[i] - np.nanmean(numberOfIcmpDstUnreachablePackets[i-windowSize: i-1]))) + "," + str(numberOfIcmpDstUnreachablePackets[i]) + "," + str(np.nanmean(numberOfIcmpDstUnreachablePackets[i-windowSize: i-1])))
                    alert = {
                        "Time": rec.stime,
                        "Gateway": systemId,
                        "Change": abs(numberOfIcmpDstUnreachablePackets[i] - np.nanmean(numberOfIcmpDstUnreachablePackets[i-windowSize: i-1])),
                        "Value": numberOfIcmpDstUnreachablePackets[i],
                        "Mean_last_10": np.nanmean(numberOfIcmpDstUnreachablePackets[i-windowSize: i-1]),
                        "Real_label": int(isAttack(rec.stime)),
                        "Attack_type": "Flooding"
                        }
                    mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

           #Push the sliding window
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1
 
        records.append(rec)

    infile.close()
    f.close()


#icmpDstUnreachableDetection("/home/linneafg/silk-data/RawDataFromFilter/icmp3-in-sorted.rw", "2011-01-03 00:00:00", "2011-01-10 00:00:00", "oslo-gw", timedelta(minutes = 1), 10, 50, "10.01")