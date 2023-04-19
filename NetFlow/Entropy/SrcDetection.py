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
    Calculates source IP entropy and entropy rate and alerts in case of an anomaly
    Input:  
            silkFile:                       string, file with flow records sorted on time
            start:                          string, indicating the start time of the data wanted
            stop:                           string, indicating the stop time of the data wanted
            systemId:                       string, name of the system to collect and calculate on
            frequency:                      timedelta object, frequency of metric calculation
            interval:                       timedelta object, size of the sliding window which the calculation is made on
            windowSize:                     int, represents a multiplier of frequency, how far back we want to compare the value with
            thresholdSrcEntropy:            float, values over this threshold will cause an alert
            thresholdSrcEntropyRate:        float, values over this threshold will cause an alert
            attackDate:                     string, date of the attack the calculations are made on
'''
def detectionSrc(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdSrcEntropy, thresholdSrcEntropyRate, attackDate):
    #Open files to write alerts to
    TPsrcEntropyFile = open("Detections/Entropy/NetFlow/TP.SourceIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TPsrcEntropyRateFile = open("Detections/Entropy/NetFlow/TP.SourceIPEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    TPsrcEntropyFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    TPsrcEntropyRateFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open files to write alerts to
    FPsrcEntropyFile = open("Detections/Entropy/NetFlow/FP.SourceIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FPsrcEntropyRateFile = open("Detections/Entropy/NetFlow/FP.SourceIPEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    FPsrcEntropyFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    FPsrcEntropyRateFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open files to write alerts to
    FNsrcEntropyFile = open("Detections/Entropy/NetFlow/FN.SourceIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FNsrcEntropyRateFile = open("Detections/Entropy/NetFlow/FN.SourceIPEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    FNsrcEntropyFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    FNsrcEntropyRateFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open files to write alerts to
    TNsrcEntropyFile = open("Detections/Entropy/NetFlow/TN.SourceIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TNsrcEntropyRateFile = open("Detections/Entropy/NetFlow/TN.SourceIPEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    json_file_sip = open("NetFlow/Entropy/Calculations/MinMax.sip."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_sip = json.load(json_file_sip)
    json_file_sip_rate = open("NetFlow/Entropy/Calculations/MinMax.sip_rate."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_sip_rate = json.load(json_file_sip_rate)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'mosquitto'
    MQTT_PORT = 1883
    MQTT_USER = 'srcEntropyDetectionNetFlow'
    MQTT_PASSWORD = 'srcEntropyDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("Source flow entropy published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("SourceFlowEntropyDetectionNetFlow")
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
    
    ipSrcArray = []
    ipSrcRateArray = []

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
            #Find the probability distribution based on how many packets there is in each source flow in this time interval
            PiSIP, ns = ipSourceDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropySip = generalizedEntropy(10,PiSIP)
            ipSrcArray.append(entropySip)
            #Calculate the generalized entropy rate of this distribution
            ipSrcRateArray.append(entropySip/ns)

            attack = isAttack(rec.stime - frequency, rec.stime)
            #If there is enough stored values to compare with we compare the difference of each metric with a threshold
            if i >=windowSize:
                change = ipSrcArray[i] - np.nanmean(ipSrcArray[i-windowSize: i-1])
                change_r = ipSrcRateArray[i] - np.nanmean(ipSrcRateArray[i-windowSize: i-1])
                
                if change < 0 and change_r < 0:
                    attackType = "Low-Rate"
                elif change_r < 0:
                    attackType = "Flooding"
                else:
                    attackType = ""
                if abs(change) > thresholdSrcEntropy:
                    alert = {
                        "sTime": rec.stime - frequency,
                        "eTime": rec.stime,
                        "Gateway": systemId,
                        "Deviation_score": normalization(abs(change), maxmin_sip["minimum"], maxmin_sip["maximum"]),
                        "Change": abs(change),
                        "Value": ipSrcArray[i],
                        "Mean_last_10": np.nanmean(ipSrcArray[i-windowSize: i-1]),
                        "Real_label": int(attack),
                        "Attack_type": attackType
                        }
                    mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
                if abs(change_r) > thresholdSrcEntropyRate:
                    alert = {
                        "sTime": rec.stime - frequency,
                        "eTime": rec.stime,
                        "Gateway": systemId,
                        "Deviation_score": normalization(abs(change_r), maxmin_sip_rate["minimum"], maxmin_sip_rate["maximum"]),
                        "Change": abs(change_r),
                        "Value": ipSrcRateArray[i],
                        "Mean_last_10": np.nanmean(ipSrcRateArray[i-windowSize: i-1]),
                        "Real_label": int(attack),
                        "Attack_type": attackType
                        }
                    mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
                
                line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + normalization(abs(change), maxmin_sip["minimum"], maxmin_sip["maximum"]) + ","+ str(abs(change)) + "," + str(ipSrcArray[i]) + "," + str(np.nanmean(ipSrcArray[i-windowSize: i-1]))
                if abs(change) > thresholdSrcEntropy and attack:
                    TPsrcEntropyFile.write(line)
                elif abs(change) > thresholdSrcEntropy and not attack:
                    FPsrcEntropyFile.write(line)
                elif abs(change) <= thresholdSrcEntropy and attack:
                    FNsrcEntropyFile.write(line)
                elif abs(change) <= thresholdSrcEntropy and not attack:
                    TNsrcEntropyFile.write(line)
                
                line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + normalization(abs(change_r), maxmin_sip_rate["minimum"], maxmin_sip_rate["maximum"]) + ","+ str(abs(change_r)) + "," + str(ipSrcRateArray[i]) + "," + str(np.nanmean(ipSrcRateArray[i-windowSize: i-1]))
                if abs(change_r) > thresholdSrcEntropyRate and attack:
                    TPsrcEntropyRateFile.write(line)
                elif abs(change_r) > thresholdSrcEntropyRate and not attack:
                    FPsrcEntropyRateFile.write(line)
                elif abs(change_r) <= thresholdSrcEntropyRate and attack:
                    FNsrcEntropyRateFile.write(line)
                elif abs(change_r) <= thresholdSrcEntropyRate and not attack:
                    TNsrcEntropyRateFile.write(line)
            else:
                line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ")
                if attack:
                    FNsrcEntropyFile.write(line)
                    FNsrcEntropyRateFile.write(line)
                elif not attack:
                    TNsrcEntropyFile.write(line)
                    TNsrcEntropyRateFile.write(line)
            #Push the sliding window
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1

        records.append(rec)
    
           
    TPsrcEntropyFile.close()
    TPsrcEntropyRateFile.close()
    FPsrcEntropyFile.close()
    FPsrcEntropyRateFile.close()
    FNsrcEntropyFile.close()
    FNsrcEntropyRateFile.close()
    TNsrcEntropyFile.close()
    TNsrcEntropyRateFile.close()
    infile.close()
    