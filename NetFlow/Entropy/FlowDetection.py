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
    #Open files to write alerts to
    flowEntropyFile = open("Detections/Entropy/NetFlow/FlowEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    flowEntropyRateFile = open("Detections/Entropy/NetFlow/FlowEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    flowFile = open("Detections/Threshold/NetFlow/NumberOfFlows."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    
    #Write the column titles to the files
    flowEntropyFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    flowEntropyRateFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))
    flowFile.write("Time,Change,Value,Mean_last_"+ str(windowSize))

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
            lastSizes = 0
            for size in sizes:
                lastSizes += size
            thisMinuteSize = len(records) - lastSizes
            sizes.append(thisMinuteSize)
            windowTime += frequency
        #Aggregate flows into the specified time interval
        if rec.stime > startTime + interval:
            #Find the probability distribution based on how many packets there is in each bi-directional flow in this time interval
            PiF, nf = flowDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropyFlow = generalizedEntropy(10, PiF)
            flowArray.append(entropyFlow)
            #Calculate the generalized entropy rate of this distribution
            flowRateArray.append(entropyFlow/nf)

            #Store the number of bi-directional flows in this time interval
            numberOfFlows.append(nf)
            
            #If there is enough stored values to compare with we compare the difference of each metric with a threshold
            if i >=windowSize:
                if flowArray[i] - np.nanmean(flowArray[i-windowSize: i-1]) < 0 and flowRateArray[i] - np.nanmean(flowRateArray[i-windowSize: i-1]) < 0:
                    attackType = "Low-Rate"
                elif flowRateArray[i] - np.nanmean(flowRateArray[i-windowSize: i-1]) < 0:
                    attackType = "Flooding"
                else:
                    attackType = ""
                if abs(flowArray[i] - np.nanmean(flowArray[i-windowSize: i-1])) > thresholdFlowEntropy:
                    flowEntropyFile.write("\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(flowArray[i] - np.nanmean(flowArray[i-windowSize: i-1]))) + "," + str(flowArray[i]) + "," + str(np.nanmean(flowArray[i-windowSize: i-1])))
                    alert = {
                        "sTime": rec.stime - frequency,
                        "eTime": rec.stime,
                        "Gateway": systemId,
                        "Change": abs(flowArray[i] - np.nanmean(flowArray[i-windowSize: i-1])),
                        "Deviation_score": normalization(abs(flowArray[i] - np.nanmean(flowArray[i-windowSize: i-1])),maxmin_flow["minimum"], maxmin_flow["maximum"]),
                        "Value": flowArray[i],
                        "Mean_last_10": np.nanmean(flowArray[i-windowSize: i-1]),
                        "Real_label": int(isAttack(rec.stime)),
                        "Attack_type": attackType
                        }
                    mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
                if abs(flowRateArray[i] - np.nanmean(flowRateArray[i-windowSize: i-1])) > thresholdFlowEntropyRate:
                    flowEntropyRateFile.write("\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(flowRateArray[i] - np.nanmean(flowRateArray[i-windowSize: i-1]))) + "," + str(flowRateArray[i]) + "," + str(np.nanmean(flowRateArray[i-windowSize: i-1])))
                    alert = {
                        "sTime": rec.stime - frequency,
                        "eTime": rec.stime,
                        "Gateway": systemId,
                        "Change": abs(flowRateArray[i] - np.nanmean(flowRateArray[i-windowSize: i-1])),
                        "Deviation_score": normalization(abs(flowRateArray[i] - np.nanmean(flowRateArray[i-windowSize: i-1])),maxmin_flow_rate["minimum"], maxmin_flow_rate["maximum"]),
                        "Value": flowRateArray[i],
                        "Mean_last_10": np.nanmean(flowRateArray[i-windowSize: i-1]),
                        "Real_label": int(isAttack(rec.stime)),
                        "Attack_type": attackType
                        }
                    mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
                if abs(numberOfFlows[i] - np.nanmean(numberOfFlows[i-windowSize: i-1])) > thresholdNumberOfFlows:
                    flowFile.write("\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(abs(numberOfFlows[i] - np.nanmean(numberOfFlows[i-windowSize: i-1]))) + "," + str(numberOfFlows[i]) + "," + str(np.nanmean(numberOfFlows[i-windowSize: i-1])))
                    alert = {
                        "sTime": rec.stime - frequency,
                        "eTime": rec.stime,
                        "Gateway": systemId,
                        "Change": abs(numberOfFlows[i] - np.nanmean(numberOfFlows[i-windowSize: i-1])),
                        "Deviation_score": normalization(abs(numberOfFlows[i] - np.nanmean(numberOfFlows[i-windowSize: i-1])), maxmin_nf["minimum"], maxmin_nf["maximum"]),
                        "Value": numberOfFlows[i],
                        "Mean_last_10": np.nanmean(numberOfFlows[i-windowSize: i-1]),
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
    
    flowEntropyFile.close()
    flowEntropyRateFile.close()
    flowFile.close()

    infile.close()
    