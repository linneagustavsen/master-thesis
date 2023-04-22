from matplotlib.path import Path
from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime
import numpy as np
import json
import paho.mqtt.client as mqtt

from HelperFunctions.IsAttack import isAttack
from HelperFunctions.Normalization import normalization

'''
    Calculates bi-directional flow entropy and entropy rate and alerts in case of an anomaly
    Input:  
            silkFile:                       string, file with flow records sorted on time
            start:                          string, indicating the start time of the data wanted
            stop:                           string, indicating the stop time of the data wanted
            systemId:                       string, name of the system to collect and calculate on
            frequency:                      timedelta object, frequency of metric calculation
            interval:                       timedelta object, size of the sliding window which the calculation is made on
            windowSize:                     int, represents a multiplier of frequency, how far back we want to compare the value with
            thresholdFlowEntropy:           float, values over this threshold will cause an alert
            thresholdFlowEntropyRate:       float, values over this threshold will cause an alert
            thresholdNumberOfFlows:         int, values over this threshold will cause an alert
            attackDate:                     string, date of the attack the calculations are made on
'''
def detectionFlow(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdFlowEntropy, thresholdFlowEntropyRate, thresholdNumberOfFlows, attackDate):
    p = Path('Detections')
    q = p / 'Entropy' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    r = p / 'Threshold' / 'NetFlow'
    if not r.exists():
        r.mkdir(parents=True)
    #Open files to write alerts to
    TPflowEntropyFile = open(str(q) + "/TP.FlowEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TPflowEntropyRateFile = open(str(q) + "/TP.FlowEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TPflowFile = open(str(r) + "TP.NumberOfFlows."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    TPflowEntropyFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    TPflowEntropyRateFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    TPflowFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open files to write alerts to
    FPflowEntropyFile = open(str(q) + "/FP.FlowEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FPflowEntropyRateFile = open(str(q) + "/FP.FlowEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FPflowFile = open(str(r) + "FP.NumberOfFlows."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    
    #Write the column titles to the files
    FPflowEntropyFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    FPflowEntropyRateFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    FPflowFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open files to write alerts to
    FNflowEntropyFile = open(str(q) + "/FN.FlowEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FNflowEntropyRateFile = open(str(q) + "/FN.FlowEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FNflowFile = open(str(r) + "FN.NumberOfFlows."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    
    #Write the column titles to the files
    FNflowEntropyFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    FNflowEntropyRateFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    FNflowFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open files to write alerts to
    TNflowEntropyFile = open(str(q) + "/TN.FlowEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TNflowEntropyRateFile = open(str(q) + "/TN.FlowEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TNflowFile = open(str(r) + "TN.NumberOfFlows."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    
    #Write the column titles to the files
    TNflowEntropyFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    TNflowEntropyRateFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    TNflowFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    json_file_flow = open("NetFlow/Entropy/Calculations/MinMax.flow."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_flow = json.load(json_file_flow)
    json_file_flow_rate = open("NetFlow/Entropy/Calculations/MinMax.f_rate."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_flow_rate = json.load(json_file_flow_rate)
    json_file_nf = open("NetFlow/Entropy/Calculations/MinMax.nf."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_nf = json.load(json_file_nf)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'mosquitto'
    MQTT_PORT = 1883
    MQTT_USER = 'flowEntropyDetectionNetFlow'
    MQTT_PASSWORD = 'flowEntropyDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("Bi-directional flow entropy detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("BidirectionalFlowEntropyDetectionNetFlow")
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
    
    flowArray = []
    flowRateArray = []

    numberOfFlows = []

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
            #Find the probability distribution based on how many packets there is in each bi-directional flow in this time interval
            PiF, nf = flowDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropyFlow = generalizedEntropy(10, PiF)
            flowArray.append(entropyFlow)
            #Calculate the generalized entropy rate of this distribution
            flowRateArray.append(entropyFlow/nf)

            #Store the number of bi-directional flows in this time interval
            numberOfFlows.append(nf)
            
            attack = isAttack(rec.stime - frequency, rec.stime)
            #If there is enough stored values to compare with we compare the difference of each metric with a threshold
            if i >=windowSize:
                change = flowArray[i] - np.nanmean(flowArray[i-windowSize: i-1])
                change_r = flowRateArray[i] - np.nanmean(flowRateArray[i-windowSize: i-1])
                change_nf = numberOfFlows[i] - np.nanmean(numberOfFlows[i-windowSize: i-1])
                
                if change < 0 and change_r < 0:
                    attackType = "Low-Rate"
                elif change_r < 0:
                    attackType = "Flooding"
                else:
                    attackType = ""
                if abs(change) > thresholdFlowEntropy:
                    alert = {
                        "sTime": (rec.stime - frequency).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "Change": abs(change),
                        "Deviation_score": normalization(abs(change),maxmin_flow["minimum"], maxmin_flow["maximum"]),
                        "Value": flowArray[i],
                        "Mean_last_10": np.nanmean(flowArray[i-windowSize: i-1]),
                        "Real_label": int(attack),
                        "Attack_type": attackType
                        }
                    mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
                if abs(change_r) > thresholdFlowEntropyRate:
                    alert = {
                        "sTime": (rec.stime - frequency).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "Change": abs(change_r),
                        "Deviation_score": normalization(abs(change_r),maxmin_flow_rate["minimum"], maxmin_flow_rate["maximum"]),
                        "Value": flowRateArray[i],
                        "Mean_last_10": np.nanmean(flowRateArray[i-windowSize: i-1]),
                        "Real_label": int(attack),
                        "Attack_type": attackType
                        }
                    mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
                if abs(change_nf) > thresholdNumberOfFlows:
                    alert = {
                        "sTime": (rec.stime - frequency).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "Change": abs(change_nf),
                        "Deviation_score": normalization(abs(change_nf), maxmin_nf["minimum"], maxmin_nf["maximum"]),
                        "Value": numberOfFlows[i],
                        "Mean_last_10": np.nanmean(numberOfFlows[i-windowSize: i-1]),
                        "Real_label": int(attack),
                        "Attack_type": attackType
                        }
                    mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
                
                line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(normalization(abs(change), maxmin_flow["minimum"], maxmin_flow["maximum"])) + ","+ str(abs(change)) + "," + str(flowArray[i]) + "," + str(np.nanmean(flowArray[i-windowSize: i-1]))
                if abs(change) > thresholdFlowEntropy and attack:
                    TPflowEntropyFile.write(line)
                elif abs(change) > thresholdFlowEntropy and not attack:
                    FPflowEntropyFile.write(line)
                elif abs(change) <= thresholdFlowEntropy and attack:
                    FNflowEntropyFile.write(line)
                elif abs(change) <= thresholdFlowEntropy and not attack:
                    TNflowEntropyFile.write(line)
                
                line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(normalization(abs(change_r), maxmin_flow_rate["minimum"], maxmin_flow_rate["maximum"])) + ","+  str(abs(change_r)) + "," + str(flowRateArray[i]) + "," + str(np.nanmean(flowRateArray[i-windowSize: i-1]))
                if abs(change_r) > thresholdFlowEntropyRate and attack:
                    TPflowEntropyRateFile.write(line)
                elif abs(change_r) > thresholdFlowEntropyRate and not attack:
                    FPflowEntropyRateFile.write(line)
                elif abs(change_r) <= thresholdFlowEntropyRate and attack:
                    FNflowEntropyRateFile.write(line)
                elif abs(change_r) <= thresholdFlowEntropyRate and not attack:
                    TNflowEntropyRateFile.write(line)
                
                line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(normalization(abs(change_nf), maxmin_nf["minimum"], maxmin_nf["maximum"])) + ","+ str(abs(change_nf)) + "," + str(numberOfFlows[i]) + "," + str(np.nanmean(numberOfFlows[i-windowSize: i-1]))
                if abs(change_nf) > thresholdNumberOfFlows and attack:
                    TPflowFile.write(line)
                elif abs(change_nf) > thresholdNumberOfFlows and not attack:
                    FPflowFile.write(line)
                elif abs(change_nf) <= thresholdNumberOfFlows and attack:
                    FNflowFile.write(line)
                elif abs(change_nf) <= thresholdNumberOfFlows and not attack:
                    TNflowFile.write(line)
            else:
                line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ")
                if attack:
                    FNflowEntropyFile.write(line)
                    FNflowEntropyRateFile.write(line)
                    FNflowFile.write(line)
                elif not attack:
                    TNflowEntropyFile.write(line)
                    TNflowEntropyRateFile.write(line)
                    TNflowFile.write(line)
            #Push the sliding window
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1
        records.append(rec)
    
    TPflowEntropyFile.close()
    FPflowEntropyFile.close()
    FNflowEntropyFile.close()
    TNflowEntropyFile.close()
    TPflowEntropyRateFile.close()
    FPflowEntropyRateFile.close()
    FNflowEntropyRateFile.close()
    TNflowEntropyRateFile.close()
    TPflowFile.close()
    FPflowFile.close()
    FNflowFile.close()
    TNflowFile.close()

    infile.close()
    