from pathlib import Path
from silk import *
from HelperFunctions.Distributions import *
from datetime import datetime,timedelta
import numpy as np
import paho.mqtt.client as mqtt
import json
from HelperFunctions.IsAttack import isAttack
from HelperFunctions.Normalization import normalization
from HelperFunctions.SimulateRealTime import simulateRealTime

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
    p = Path('Detections')
    q = p / 'Threshold' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    #Open file to write alerts to
    f = open(str(q) + "/ICMPDstUnreachable."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #Write the column titles to the files
    f.write("Time,Change,Value,Mean_last_"+ str(windowSize))

     #Open file to write alerts to
    TPICMPDstUnreachableFile = open("Detections/Threshold/NetFlow/TP.ICMPDstUnreachable."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    TPICMPDstUnreachableFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open file to write alerts to
    FPICMPDstUnreachableFile = open("Detections/Threshold/NetFlow/FP.ICMPDstUnreachable."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    FPICMPDstUnreachableFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open file to write alerts to
    FNICMPDstUnreachableFile = open("Detections/Threshold/NetFlow/FN.ICMPDstUnreachable."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    FNICMPDstUnreachableFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open file to write alerts to
    TNICMPDstUnreachableFile = open("Detections/Threshold/NetFlow/TN.ICMPDstUnreachable."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    TNICMPDstUnreachableFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    
    p = Path('NetFlow')
    q = p / 'Threshold' / 'Calculations'
    if not q.exists():
        q = Path('Threshold')
        q = q / 'Calculations'
    json_file = open(str(q) + "/MinMax.icmp_dst_unreachable."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin = json.load(json_file)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'icmpDstUnreachableDetectionNetFlow'
    MQTT_PASSWORD = 'icmpDstUnreachableDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("ICMP destination unreachable detection published to topic", MQTT_TOPIC)

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
            continue
        if rec.stime < startTime:
            continue
        #Implement the sliding window
        if rec.stime > windowTime + frequency:
            lastSizes  = sum(sizes)
            thisMinuteSize = len(records) - lastSizes
            sizes.append(thisMinuteSize)
            windowTime += frequency
        if rec.stime > startTime + interval:
            #Find the number of ICMP Destination unavailable packets in this time interval
            numberOfIcmpDstUnreachablePackets.append(numberOfPackets(records))

            attack = isAttack(rec.stime - frequency, rec.stime)
            #If there is enough stored values to compare with we compare the difference of the metric with a threshold
            if i >= windowSize:
                change = numberOfIcmpDstUnreachablePackets[i] - np.nanmean(numberOfIcmpDstUnreachablePackets[i-windowSize: i-1])

                simulateRealTime(datetime.now(), rec.stime, attackDate)
                if abs(change) > threshold:
                    alert = {
                        "sTime": (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "Deviation_score": normalization(abs(change), maxmin["minimum"], maxmin["maximum"]),
                        "protocol": rec.protocol,
                        "Change": abs(change),
                        "Value": numberOfIcmpDstUnreachablePackets[i],
                        "Mean_last_10": np.nanmean(numberOfIcmpDstUnreachablePackets[i-windowSize: i-1]),
                        "Real_label": int(attack),
                        "Attack_type": "Flooding"
                        }
                    mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
                
                line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(normalization(abs(change), maxmin["minimum"], maxmin["maximum"])) + ","+ str(abs(change)) + "," + str(numberOfIcmpDstUnreachablePackets[i]) + "," + str(np.nanmean(numberOfIcmpDstUnreachablePackets[i-windowSize: i-1]))
                if abs(change) > threshold and attack:
                    TPICMPDstUnreachableFile.write(line)
                elif abs(change) > threshold and not attack:
                    FPICMPDstUnreachableFile.write(line)
                elif abs(change) <= threshold and attack:
                    FNICMPDstUnreachableFile.write(line)
                elif abs(change) <= threshold and not attack:
                    TNICMPDstUnreachableFile.write(line)
            else:
                line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ")
                if attack:
                    FNICMPDstUnreachableFile.write(line)
                elif not attack:
                    TNICMPDstUnreachableFile.write(line)
           #Push the sliding window
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1
 
        records.append(rec)

    infile.close()
    TPICMPDstUnreachableFile.close()
    FPICMPDstUnreachableFile.close()
    FNICMPDstUnreachableFile.close()
    TNICMPDstUnreachableFile.close()


#icmpDstUnreachableDetection("/home/linneafg/silk-data/RawDataFromFilter/icmp3-in-sorted.rw", "2011-01-03 00:00:00", "2011-01-10 00:00:00", "oslo-gw", timedelta(minutes = 1), 10, 50, "10.01")

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
silkFile = pathToRawFiles+systemId + "/"+ baseFile
windowSize = 10

silkFile = pathToRawFiles+systemId + "/icmp3-two-hours-2011-02-08_10-12-sorted.rw"
icmpDstUnreachableDetection(silkFile, start, stop, systemId, frequency, interval, windowSize, 0, attackDate)