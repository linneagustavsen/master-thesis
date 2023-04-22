from pathlib import Path
from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime
import numpy as np
import paho.mqtt.client as mqtt
import json
from HelperFunctions.IsAttack import isAttack
from HelperFunctions.Normalization import normalization


'''
    Calculates entropy and alerts in case of an anomaly
    Input:  silkFile:       string, file with flow records sorted on time
            start:          string, indicating the start time of the data wanted
            stop:           string, indicating the stop time of the data wanted
            systemId:       string, name of the system to collect and calculate on
            frequency:      timedelta object, frequency of metric calculation
            interval:       timedelta object, size of the sliding window which the calculation is made on
            windowSize:     int, represents a multiplier of frequency, how far back we want to compare the value with
            thresholdSrc:   float, values over this threshold will cause an alert
            thresholdDst:   float, values over this threshold will cause an alert
            thresholdFlow:  float, values over this threshold will cause an alert
            attackDate:     string, date of the attack the calculations are made on
'''
def synEntropyDetection(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdSrc, thresholdDst, thresholdFlow, attackDate):
    p = Path('Detections')
    q = p / 'Entropy' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    #Open files to write alerts to
    TPsrcFile = open(str(q) + "/TP.SYNSourceIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TPdstFile = open(str(q) + "/TP.SYNDestinationIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TPflowFile = open(str(q) + "/TP.SYNFlowIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    
    #Write the column titles to the files
    TPsrcFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    TPdstFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    TPflowFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open files to write alerts to
    FPsrcFile = open(str(q) + "/FP.SYNSourceIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FPdstFile = open(str(q) + "/FP.SYNDestinationIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FPflowFile = open(str(q) + "/FP.SYNFlowIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    
    #Write the column titles to the files
    FPsrcFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    FPdstFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    FPflowFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open files to write alerts to
    FNsrcFile = open(str(q) + "/FN.SYNSourceIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FNdstFile = open(str(q) + "/FN.SYNDestinationIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FNflowFile = open(str(q) + "/FN.SYNFlowIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    
    #Write the column titles to the files
    FNsrcFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    FNdstFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    FNflowFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open files to write alerts to
    TNsrcFile = open(str(q) + "/TN.SYNSourceIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TNdstFile = open(str(q) + "/TN.SYNDestinationIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TNflowFile = open(str(q) + "/TN.SYNFlowIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    
    #Write the column titles to the files
    TNsrcFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    TNdstFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    TNflowFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))


    #Open file to write alerts to
    srcEntropyFile = open(str(q) + "/SYNSourceIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    dstEntropyFile = open(str(q) + "/SYNDestinationIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    srcFile = open(str(q) + "/SYNFlowIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    
    json_file_src = open("NetFlow/Entropy/Calculations/MinMax.SYN_src."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_src = json.load(json_file_src)
    json_file_dst = open("NetFlow/Entropy/Calculations/MinMax.SYN_dst."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_dst = json.load(json_file_dst)
    json_file_flow = open("NetFlow/Entropy/Calculations/MinMax.SYN_flow."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_flow = json.load(json_file_flow)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'mosquitto'
    MQTT_PORT = 1883
    MQTT_USER = 'synEntropyDetectionNetFlow'
    MQTT_PASSWORD = 'synEntropyDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("SYN entropy detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("SYNEntropyDetectionNetFlow")
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
    entropyOfSynPacketsPerSrc = []
    entropyOfSynPacketsPerDst = []
    entropyOfSynPacketsPerFlow = []

    i = 0
    sizes = []
    lastMinuteSize = 0
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
            #Find the probability distribution based on how many SYN packets there is in each source flow in this time interval
            PiSIP, ns = ipSourceDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropySip = generalizedEntropy(10,PiSIP)
            entropyOfSynPacketsPerSrc.append(entropySip)

            #Find the probability distribution based on how many SYN packets there is in each destination flow in this time interval
            PiDIP, nd = ipDestinationDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropyDip = generalizedEntropy(10,PiDIP)
            entropyOfSynPacketsPerDst.append(entropyDip)

            #Find the probability distribution based on how many SYN packets there is in each bi-directional flow in this time interval
            PiF, nf = uniDirFlowDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropyFlow = generalizedEntropy(10,PiF)
            entropyOfSynPacketsPerFlow.append(entropyFlow)
            
            attack = isAttack(rec.stime - frequency, rec.stime)
            #If there is enough stored values to compare with we compare the difference of each metric with a threshold
            if i >=windowSize:
                change_src = entropyOfSynPacketsPerSrc[i] - np.nanmean(entropyOfSynPacketsPerSrc[i-windowSize: i-1])
                change_dst = entropyOfSynPacketsPerDst[i] - np.nanmean(entropyOfSynPacketsPerDst[i-windowSize: i-1])
                change_flow = entropyOfSynPacketsPerFlow[i] - np.nanmean(entropyOfSynPacketsPerFlow[i-windowSize: i-1])
            
                if abs(change_src) > thresholdSrc:
                    alert = {
                       "sTime": rec.stime- frequency,
                        "eTime": rec.stime,
                        "Gateway": systemId,
                        "Deviation_score": normalization(abs(change_src), maxmin_src["minimum"], maxmin_src["maximum"]),
                        "protocol": rec.protocol,
                        "Change": abs(change_src),
                        "Value": entropyOfSynPacketsPerSrc[i],
                        "Mean_last_10": np.nanmean(entropyOfSynPacketsPerSrc[i-windowSize: i-1]),
                        "Real_label": int(attack),
                        "Attack_type": "SYN Flood"
                        }
                    mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
                if abs(change_dst) > thresholdDst:
                    alert = {
                        "sTime": rec.stime- frequency,
                        "eTime": rec.stime,
                        "Gateway": systemId,
                        "Deviation_score": normalization(abs(change_dst), maxmin_dst["minimum"], maxmin_dst["maximum"]),
                        "protocol": rec.protocol,
                        "Change": abs(change_dst),
                        "Value": entropyOfSynPacketsPerDst[i],
                        "Mean_last_10": np.nanmean(entropyOfSynPacketsPerDst[i-windowSize: i-1]),
                        "Real_label": int(attack),
                        "Attack_type": "SYN Flood"
                        }
                    mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
                if abs(change_flow) > thresholdFlow:
                    alert = {
                        "sTime": rec.stime- frequency,
                        "eTime": rec.stime,
                        "Gateway": systemId,
                        "Deviation_score": normalization(abs(change_flow), maxmin_flow["minimum"], maxmin_flow["maximum"]),
                        "protocol": rec.protocol,
                        "Change": abs(change_flow),
                        "Value": entropyOfSynPacketsPerFlow[i],
                        "Mean_last_10": np.nanmean(entropyOfSynPacketsPerFlow[i-windowSize: i-1]),
                        "Real_label": int(attack),
                        "Attack_type": "SYN Flood"
                        }
                    mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
            
                line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + normalization(abs(change_src), maxmin_src["minimum"], maxmin_src["maximum"]) + ","+  str(abs(change_src)) + "," + str(entropyOfSynPacketsPerSrc[i]) + "," + str(np.nanmean(entropyOfSynPacketsPerSrc[i-windowSize: i-1]))
                if abs(change_src) > thresholdSrc and attack:
                    TPsrcFile.write(line)
                elif abs(change_src) > thresholdSrc and not attack:
                    FPsrcFile.write(line)
                elif abs(change_src) <= thresholdSrc and attack:
                    FNsrcFile.write(line)
                elif abs(change_src) <= thresholdSrc and not attack:
                    TNsrcFile.write(line)
                
                line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + normalization(abs(change_dst), maxmin_dst["minimum"], maxmin_dst["maximum"]) + ","+ str(abs(change_dst)) + "," + str(entropyOfSynPacketsPerDst[i]) + "," + str(np.nanmean(entropyOfSynPacketsPerDst[i-windowSize: i-1]))
                if abs(change_dst) > thresholdDst and attack:
                    TPdstFile.write(line)
                elif abs(change_dst) > thresholdDst and not attack:
                    FPdstFile.write(line)
                elif abs(change_dst) <= thresholdDst and attack:
                    FNdstFile.write(line)
                elif abs(change_dst) <= thresholdDst and not attack:
                    TNdstFile.write(line)
                
                line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + normalization(abs(change_flow), maxmin_flow["minimum"], maxmin_flow["maximum"]) + ","+ str(abs(change_flow)) + "," + str(entropyOfSynPacketsPerFlow[i]) + "," + str(np.nanmean(entropyOfSynPacketsPerFlow[i-windowSize: i-1]))
                if abs(change_flow) > thresholdFlow and attack:
                    TPflowFile.write(line)
                elif abs(change_flow) > thresholdFlow and not attack:
                    FPflowFile.write(line)
                elif abs(change_flow) <= thresholdFlow and attack:
                    FNflowFile.write(line)
                elif abs(change_flow) <= thresholdFlow and not attack:
                    TNflowFile.write(line)
            else:
                line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ")
                if attack:
                    FNsrcFile.write(line)
                    FNdstFile.write(line)
                    FNflowFile.write(line)
                elif not attack:
                    TNsrcFile.write(line)
                    TNdstFile.write(line)
                    TNflowFile.write(line)
            #Push the sliding window
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1
        
        records.append(rec)
            

    infile.close()
    TPsrcFile.close()
    FPsrcFile.close()
    FNsrcFile.close()
    TNsrcFile.close()
    TPdstFile.close()
    FPdstFile.close()
    FNdstFile.close()
    TNdstFile.close()
    TPflowFile.close()
    FPflowFile.close()
    FNflowFile.close()
    TNflowFile.close()

