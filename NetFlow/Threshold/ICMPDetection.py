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
from HelperFunctions.SimulateRealTime import simulateRealTime

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
    p = Path('Detections')
    q = p / 'Threshold' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    #Open file to write alerts to
    TPicmpRatioFile = open(str(q) + "/TP.ICMPRatio."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TPicmpPacketsFile = open(str(q) + "/TP.ICMPPackets."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    
    #Write the column titles to the files
    TPicmpRatioFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    TPicmpPacketsFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open file to write alerts to
    FPicmpRatioFile = open(str(q) + "/FP.ICMPRatio."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FPicmpPacketsFile = open(str(q) + "/FP.ICMPPackets."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    
    #Write the column titles to the files
    FPicmpRatioFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    FPicmpPacketsFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open file to write alerts to
    FNicmpRatioFile = open(str(q) + "/FN.ICMPRatio."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FNicmpPacketsFile = open(str(q) + "/FN.ICMPPackets."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    
    #Write the column titles to the files
    FNicmpRatioFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    FNicmpPacketsFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open file to write alerts to
    TNicmpRatioFile = open(str(q) + "/TN.ICMPRatio."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TNicmpPacketsFile = open(str(q) + "/TN.ICMPPackets."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    
    #Write the column titles to the files
    TNicmpRatioFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    TNicmpPacketsFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    p = Path('NetFlow')
    q = p / 'Threshold' / 'Calculations'
    if not q.exists():
        q = Path('Threshold')
        q = q / 'Calculations'
    json_file_packets = open(str(q) + "/MinMax.icmp_packets."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_packets = json.load(json_file_packets)
    json_file_ratio = open(str(q) + "/MinMax.icmp_ratio."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_ratio = json.load(json_file_ratio)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'icmpDetectionNetFlow'
    MQTT_PASSWORD = 'icmpDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("ICMP detection published to topic", MQTT_TOPIC)

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
        if rec.etime > stopTime + frequency:
            continue
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
            #Find the ratio of ICMP packets in this time interval
            icmpRatio, icmpPackets = icmpDistribution(records)
            icmpRatioArray.append(icmpRatio)
            icmpPacketsArray.append(icmpPackets)

            attack = isAttack(rec.stime - frequency, rec.stime)
            #If there is enough stored values to compare with we compare the difference of each metric with a threshold
            if i >=windowSize:
                change_ratio = icmpRatioArray[i] - np.nanmean(icmpRatioArray[i-windowSize: i-1])
                change_packets = icmpPacketsArray[i] - np.nanmean(icmpPacketsArray[i-windowSize: i-1])
                
                simulateRealTime(datetime.now(), rec.stime, attackDate)
                if abs(change_ratio) > thresholdICMPRatio:
                    alert = {
                        "sTime": (rec.stime - frequency).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "Deviation_score": normalization(abs(change_ratio), maxmin_ratio["minimum"], maxmin_ratio["maximum"]),
                        "Protocol": rec.protocol,
                        '''"Change": abs(change_ratio),
                        "Value": icmpRatioArray[i],
                        "Mean_last_10": np.nanmean(icmpRatioArray[i-windowSize: i-1]),'''
                        "Real_label": int(attack),
                        "Attack_type": "ICMP Flood"
                        }
                    mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

                if abs(change_packets) > thresholdNumberOfICMPPackets:
                    alert = {
                        "sTime": (rec.stime - frequency).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "Deviation_score": normalization(abs(change_packets), maxmin_packets["minimum"], maxmin_packets["maximum"]),
                        "Protocol": rec.protocol,
                        '''"Change": abs(change_packets),
                        "Value": icmpPacketsArray[i],
                        "Mean_last_10": np.nanmean(icmpPacketsArray[i-windowSize: i-1]),'''
                        "Real_label": int(attack),
                        "Attack_type": "ICMP Flood"
                        }
                    mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))

                line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(normalization(abs(change_ratio), maxmin_ratio["minimum"], maxmin_ratio["maximum"])) + ","+ str(abs(change_ratio)) + "," + str(icmpRatioArray[i]) + "," + str(np.nanmean(icmpRatioArray[i-windowSize: i-1]))
                if abs(change_ratio) > thresholdICMPRatio and attack:
                    TPicmpRatioFile.write(line)
                elif abs(change_ratio) > thresholdICMPRatio and not attack:
                    FPicmpRatioFile.write(line)
                elif abs(change_ratio) <= thresholdICMPRatio and attack:
                    FNicmpRatioFile.write(line)
                elif abs(change_ratio) <= thresholdICMPRatio and not attack:
                    TNicmpRatioFile.write(line)
                
                line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(normalization(abs(change_packets), maxmin_packets["minimum"], maxmin_packets["maximum"])) + ","+ str(abs(change_packets)) + "," + str(icmpPacketsArray[i]) + "," + str(np.nanmean(icmpPacketsArray[i-windowSize: i-1]))
                if abs(change_packets) > thresholdNumberOfICMPPackets and attack:
                    TPicmpPacketsFile.write(line)
                elif abs(change_packets) > thresholdNumberOfICMPPackets and not attack:
                    FPicmpPacketsFile.write(line)
                elif abs(change_packets) <= thresholdNumberOfICMPPackets and attack:
                    FNicmpPacketsFile.write(line)
                elif abs(change_packets) <= thresholdNumberOfICMPPackets and not attack:
                    TNicmpPacketsFile.write(line)
            else:
                line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ")
                if attack:
                    FNicmpRatioFile.write(line)
                    FNicmpPacketsFile.write(line)
                elif not attack:
                    TNicmpRatioFile.write(line)
                    TNicmpPacketsFile.write(line)
            #Push the sliding window
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1

        records.append(rec)
    
    TPicmpRatioFile.close()
    TPicmpPacketsFile.close()
    FPicmpRatioFile.close()
    FPicmpPacketsFile.close()
    FNicmpRatioFile.close()
    FNicmpPacketsFile.close()
    TNicmpRatioFile.close()
    TNicmpPacketsFile.close()

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
silkFile = pathToRawFiles+systemId + "/"+ baseFile
windowSize = 10

detectionICMP(silkFile, start, stop, systemId, frequency, interval, windowSize, 0, 0, attackDate)