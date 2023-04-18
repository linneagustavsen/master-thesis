from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime,timedelta
import numpy as np
import json
import paho.mqtt.client as mqtt
from HelperFunctions.IsAttack import isAttack
from HelperFunctions.Normalization import normalization

'''
    Calculates packet size entropy and entropy rate and alerts in case of an anomaly
    Input:  
            silkFile:                       string, file with flow records sorted on time
            start:                          string, indicating the start time of the data wanted
            stop:                           string, indicating the stop time of the data wanted
            systemId:                       string, name of the system to collect and calculate on
            frequency:                      timedelta object, frequency of metric calculation
            interval:                       timedelta object, size of the sliding window which the calculation is made on
            windowSize:                     int, represents a multiplier of frequency, how far back we want to compare the value with
            thresholdPSEntropy:             float, values over this threshold will cause an alert
            thresholdPSEntropyRate:         float, values over this threshold will cause an alert
            attackDate:                     string, date of the attack the calculations are made on
'''
def detectionPS(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdPSEntropy, thresholdPSEntropyRate, attackDate):
    #Open files to write alerts to
    packetSizeEntropyFile = open("Detections/Entropy/NetFlow/PacketSizeEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    packetSizeEntropyRateFile = open("Detections/Entropy/NetFlow/PacketSizeEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    
    #Write the column titles to the files
    packetSizeEntropyFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    packetSizeEntropyRateFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    
    json_file_ps = open("NetFlow/Entropy/Calculations/MinMax.packet_size."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_ps = json.load(json_file_ps)
    json_file_ps_rate = open("NetFlow/Entropy/Calculations/MinMax.packet_size_r."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_ps_rate = json.load(json_file_ps_rate)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'mosquitto'
    MQTT_PORT = 1883
    MQTT_USER = 'packetSizeEntropyDetectionNetFlow'
    MQTT_PASSWORD = 'packetSizeEntropyDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("Packet size entropy detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("PacketSizeEntropyDetectionNetFlow")
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

    packetSizeArray = []
    packetSizeRateArray = []
    
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
            #Find the probability distribution based on how big the packets are this time interval
            PiPS,nps = packetSizeDistributionNetFlow(records)
            #Calculate the generalized entropy of this distribution
            entropyPacketSize = generalizedEntropy(10, PiPS)
            packetSizeArray.append(entropyPacketSize)
            #Calculate the generalized entropy rate of this distribution
            packetSizeRateArray.append(entropyPacketSize/nps)

            #If there is enough stored values to compare with we compare the difference of each metric with a threshold
            if i >=windowSize:
                if packetSizeArray[i] - np.nanmean(packetSizeArray[i-windowSize: i-1]) < 0:
                        attackType = "Same protocol"
                else:
                    attackType = "Different protocols"
                if abs(packetSizeArray[i] - np.nanmean(packetSizeArray[i-windowSize: i-1])) > thresholdPSEntropy:
                    packetSizeEntropyFile.write("\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(packetSizeArray[i] - np.nanmean(packetSizeArray[i-windowSize: i-1]))) + "," + str(packetSizeArray[i]) + "," + str(np.nanmean(packetSizeArray[i-windowSize: i-1])))
                    alert = {
                        "sTime": rec.stime - frequency,
                        "eTime": rec.stime,
                        "Gateway": systemId,
                        "Deviation_score": normalization(abs(packetSizeArray[i] - np.nanmean(packetSizeArray[i-windowSize: i-1])), maxmin_ps["minimum"], maxmin_ps["maximum"]),
                        "Change": abs(packetSizeArray[i] - np.nanmean(packetSizeArray[i-windowSize: i-1])),
                        "Value": packetSizeArray[i],
                        "Mean_last_10": np.nanmean(packetSizeArray[i-windowSize: i-1]),
                        "Real_label": int(isAttack(rec.stime)),
                        "Attack_type": attackType
                    }
                    mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
                if abs(packetSizeRateArray[i] - np.nanmean(packetSizeRateArray[i-windowSize: i-1])) > thresholdPSEntropyRate:
                    packetSizeEntropyRateFile.write("\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(packetSizeRateArray[i] - np.nanmean(packetSizeRateArray[i-windowSize: i-1]))) + "," + str(packetSizeRateArray[i]) + "," + str(np.nanmean(packetSizeRateArray[i-windowSize: i-1])))
                    alert = {
                        "sTime": rec.stime - frequency,
                        "eTime": rec.stime,
                        "Gateway": systemId,
                        "Deviation_score": normalization(abs(packetSizeArray[i] - np.nanmean(packetSizeArray[i-windowSize: i-1])), maxmin_ps_rate["minimum"], maxmin_ps_rate["maximum"]),
                        "Change": abs(packetSizeRateArray[i] - np.nanmean(packetSizeRateArray[i-windowSize: i-1])),
                        "Value": packetSizeArray[i],
                        "Mean_last_10": np.nanmean(packetSizeRateArray[i-windowSize: i-1]),
                        "Real_label": int(isAttack(rec.stime)),
                        "Attack_type": attackType
                    }
                    mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
            #Push the sliding window
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1

        records.append(rec)
    
    packetSizeEntropyFile.close()
    packetSizeEntropyRateFile.close()

    infile.close()
    