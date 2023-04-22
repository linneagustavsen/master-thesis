from matplotlib.path import Path
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
    p = Path('Detections')
    q = p / 'Entropy' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    #Open files to write alerts to
    TPpacketSizeEntropyFile = open(str(q) + "/TP.PacketSizeEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TPpacketSizeEntropyRateFile = open(str(q) + "/TP.PacketSizeEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    TPpacketSizeEntropyFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    TPpacketSizeEntropyRateFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open files to write alerts to
    FPpacketSizeEntropyFile = open(str(q) + "/FP.PacketSizeEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FPpacketSizeEntropyRateFile = open(str(q) + "/FP.PacketSizeEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    FPpacketSizeEntropyFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    FPpacketSizeEntropyRateFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open files to write alerts to
    FNpacketSizeEntropyFile = open(str(q) + "/FN.PacketSizeEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FNpacketSizeEntropyRateFile = open(str(q) + "/FN.PacketSizeEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    FNpacketSizeEntropyFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    FNpacketSizeEntropyRateFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open files to write alerts to
    TNpacketSizeEntropyFile = open(str(q) + "/TN.PacketSizeEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TNpacketSizeEntropyRateFile = open(str(q) + "/TN.PacketSizeEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    TNpacketSizeEntropyFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    TNpacketSizeEntropyRateFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    
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
            lastSizes  = sum(sizes)
            thisMinuteSize = len(records) - lastSizes
            sizes.append(thisMinuteSize)
            windowTime += frequency
        #Aggregate flows into the specified time interval
        if rec.stime > startTime + interval:
            if len(records) == 0:
                startTime = startTime + frequency
                sizes.pop(0)
                records.append(rec)
                continue
            #Find the probability distribution based on how big the packets are this time interval
            PiPS,nps = packetSizeDistributionNetFlow(records)
            #Calculate the generalized entropy of this distribution
            entropyPacketSize = generalizedEntropy(10, PiPS)
            packetSizeArray.append(entropyPacketSize)
            #Calculate the generalized entropy rate of this distribution
            packetSizeRateArray.append(entropyPacketSize/nps)

            #If there is enough stored values to compare with we compare the difference of each metric with a threshold
            if i >=windowSize:
                change = packetSizeArray[i] - np.nanmean(packetSizeArray[i-windowSize: i-1])
                change_r = packetSizeRateArray[i] - np.nanmean(packetSizeRateArray[i-windowSize: i-1])
                attack = isAttack(rec.stime - frequency,rec.stime)
                if change < 0:
                        attackType = "Same protocol"
                else:
                    attackType = "Different protocols"
                if abs(change) > thresholdPSEntropy:
                    alert = {
                        "sTime": (rec.stime - frequency).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "Deviation_score": normalization(abs(change), maxmin_ps["minimum"], maxmin_ps["maximum"]),
                        "Change": abs(change),
                        "Value": packetSizeArray[i],
                        "Mean_last_10": np.nanmean(packetSizeArray[i-windowSize: i-1]),
                        "Real_label": int(attack),
                        "Attack_type": attackType
                    }
                    mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
                if abs(change_r) > thresholdPSEntropyRate:
                    alert = {
                        "sTime": (rec.stime - frequency).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "Deviation_score": normalization(abs(change), maxmin_ps_rate["minimum"], maxmin_ps_rate["maximum"]),
                        "Change": abs(change_r),
                        "Value": packetSizeArray[i],
                        "Mean_last_10": np.nanmean(packetSizeRateArray[i-windowSize: i-1]),
                        "Real_label": int(attack),
                        "Attack_type": attackType
                    }
                    mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
                
                line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(normalization(abs(change), maxmin_ps["minimum"], maxmin_ps["maximum"])) + ","+ str(abs(change)) + "," + str(packetSizeArray[i]) + "," + str(np.nanmean(packetSizeArray[i-windowSize: i-1]))
                if abs(change) > thresholdPSEntropy and attack:
                    TPpacketSizeEntropyFile.write(line)
                elif abs(change) > thresholdPSEntropy and not attack:
                    FPpacketSizeEntropyFile.write(line)
                elif abs(change) <= thresholdPSEntropy and attack:
                    FNpacketSizeEntropyFile.write(line)
                elif abs(change) <= thresholdPSEntropy and not attack:
                    TNpacketSizeEntropyFile.write(line)
                
                line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(normalization(abs(change_r), maxmin_ps_rate["minimum"], maxmin_ps_rate["maximum"])) + ","+ str(abs(change_r)) + "," + str(packetSizeRateArray[i]) + "," + str(np.nanmean(packetSizeRateArray[i-windowSize: i-1]))
                if abs(change_r) > thresholdPSEntropyRate and attack:
                    TPpacketSizeEntropyRateFile.write(line)
                elif abs(change_r) > thresholdPSEntropyRate and not attack:
                    FPpacketSizeEntropyRateFile.write(line)
                elif abs(change_r) <= thresholdPSEntropyRate and attack:
                    FNpacketSizeEntropyRateFile.write(line)
                elif abs(change_r) <= thresholdPSEntropyRate and not attack:
                    TNpacketSizeEntropyRateFile.write(line)
            else:
                line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ")
                if attack:
                    FNpacketSizeEntropyFile.write(line)
                    FNpacketSizeEntropyRateFile.write(line)
                elif not attack:
                    TNpacketSizeEntropyFile.write(line)
                    TNpacketSizeEntropyRateFile.write(line)
            #Push the sliding window
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1

        records.append(rec)
    
    TPpacketSizeEntropyFile.close()
    TPpacketSizeEntropyRateFile.close()
    FPpacketSizeEntropyFile.close()
    FPpacketSizeEntropyRateFile.close()
    FNpacketSizeEntropyFile.close()
    FNpacketSizeEntropyRateFile.close()
    TNpacketSizeEntropyFile.close()
    TNpacketSizeEntropyRateFile.close()
    

    infile.close()
    