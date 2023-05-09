from pathlib import Path
import pandas as pd
from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime, timedelta
import numpy as np
import json
import paho.mqtt.client as mqtt
from HelperFunctions.IsAttack import isAttack
from HelperFunctions.Normalization import normalization
from HelperFunctions.SimulateRealTime import simulateRealTime

'''
    Calculates destination IP entropy and entropy rate and alerts in case of an anomaly
    Input:  
            silkFile:                       string, file with flow records sorted on time
            start:                          string, indicating the start time of the data wanted
            stop:                           string, indicating the stop time of the data wanted
            systemId:                       string, name of the system to collect and calculate on
            frequency:                      timedelta object, frequency of metric calculation
            interval:                       timedelta object, size of the sliding window which the calculation is made on
            windowSize:                     int, represents a multiplier of frequency, how far back we want to compare the value with
            thresholdDstEntropy:            float, values over this threshold will cause an alert
            thresholdDstEntropyRate:        float, values over this threshold will cause an alert
            attackDate:                     string, date of the attack the calculations are made on
'''
def detectionDst(silkFile, start, stop, systemId, frequency, interval, windowSize, thresholdDstEntropy, thresholdDstEntropyRate, attackDate):
    p = Path('Detections')
    q = p / 'Entropy' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    #Open files to write alerts to
    TPdstEntropyFile = open(str(q) + "/TP.DestinationIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TPdstEntropyRateFile = open(str(q) + "/TP.DestinationIPEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    TPdstEntropyFile.write("number")
    TPdstEntropyRateFile.write("number")

    #Open files to write alerts to
    FPdstEntropyFile = open(str(q) + "/FP.DestinationIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FPdstEntropyRateFile = open(str(q) + "/FP.DestinationIPEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    FPdstEntropyFile.write("number")
    FPdstEntropyRateFile.write("number")

    #Open files to write alerts to
    FNdstEntropyFile = open(str(q) + "/FN.DestinationIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FNdstEntropyRateFile = open(str(q) + "/FN.DestinationIPEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    FNdstEntropyFile.write("number")
    FNdstEntropyRateFile.write("number")

    #Open files to write alerts to
    TNdstEntropyFile = open(str(q) + "/TN.DestinationIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TNdstEntropyRateFile = open(str(q) + "/TN.DestinationIPEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    TNdstEntropyFile.write("number")
    TNdstEntropyRateFile.write("number")
    
    p = Path('NetFlow')
    q = p / 'Entropy' / 'Calculations'
    if not q.exists():
        q = Path('Entropy')
        q = q / 'Calculations'
    json_file_dip = open(str(q) + "/MinMax.dip."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_dip = json.load(json_file_dip)
    json_file_dip_rate = open(str(q) + "/MinMax.dip_rate."+ str(int(interval.total_seconds())) +".json", "r")
    maxmin_dip_rate = json.load(json_file_dip_rate)

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'dstEntropyDetectionNetFlow'
    MQTT_PASSWORD = 'dstEntropyDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("Destination flow entropy detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("DestinationFlowEntropyDetectionNetFlow")
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)


    data = pd.read_csv("Calculations0803/Entropy/NetFlow/Metrics."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    sTime = pd.to_datetime(data["sTime"])
    eTime = pd.to_datetime(data["eTime"])


    dstEntropy = data["dstEntropy"]
    dstEntropyRate = data["dstEntropyRate"]

    attackFlows = pd.read_csv("Calculations0803/Entropy/NetFlow/AttackFlows."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
    sTimeAttacks = pd.to_datetime(attackFlows["sTime"])
    eTimeAttacks = pd.to_datetime(attackFlows["eTime"])
   
    truePositives = 0
    falsePositives = 0
    falseNegatives = 0
    trueNegatives  =0

    truePositives_r = 0
    falsePositives_r = 0
    falseNegatives_r = 0
    trueNegatives_r  =0

    #Loop through all the flow records in the input file
    for i in range(len(sTime)):
        attack = sTime[i] in sTimeAttacks.values or eTime[i] in eTimeAttacks.values
        if i >=windowSize:
            change = dstEntropy[i] - np.nanmean(dstEntropy[i-windowSize: i-1])
            change_r = dstEntropyRate[i] - np.nanmean(dstEntropyRate[i-windowSize: i-1])
            if change < 0 and change_r < 0:
                attackType = "Low-Rate"
            elif change_r < 0:
                attackType = "Flooding"
            else:
                attackType = ""

            simulateRealTime(datetime.now(), sTime[i], attackDate)
            if abs(change) > thresholdDstEntropy:
                alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change), maxmin_dip["minimum"], maxmin_dip["maximum"]),
                    "Real_label": int(attack),
                    "Attack_type": attackType
                    }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
            if abs(change_r) >  thresholdDstEntropyRate:
                alert = {
                    "sTime": sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "eTime": eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Gateway": systemId,
                    "Deviation_score": normalization(abs(change_r), maxmin_dip_rate["minimum"], maxmin_dip_rate["maximum"]),
                    "Real_label": int(attack),
                    "Attack_type": attackType
                    }
                mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
            
            if abs(change) > thresholdDstEntropy and attack:
                truePositives += 1
            elif abs(change) > thresholdDstEntropy and not attack:
                falsePositives += 1
            elif abs(change) <= thresholdDstEntropy and attack:
                falseNegatives +=1
            elif abs(change) <= thresholdDstEntropy and not attack:
                trueNegatives += 1
            
            if abs(change_r) > thresholdDstEntropyRate and attack:
                truePositives_r += 1
            elif abs(change_r) > thresholdDstEntropyRate and not attack:
                falsePositives_r += 1
            elif abs(change_r) <= thresholdDstEntropyRate and attack:
                falseNegatives_r += 1
            elif abs(change_r) <= thresholdDstEntropyRate and not attack:
                trueNegatives_r += 1
    else:
        if attack:
            falseNegatives += 1
            falseNegatives_r += 1
        elif not attack:
            trueNegatives += 1
            trueNegatives_r += 1
    TPdstEntropyFile.write(truePositives)
    FPdstEntropyFile.write(falsePositives)
    FNdstEntropyFile.write(falseNegatives)
    TNdstEntropyFile.write(trueNegatives)

    TPdstEntropyRateFile.write(truePositives_r)
    FPdstEntropyRateFile.write(falsePositives_r)
    FNdstEntropyRateFile.write(falseNegatives_r)
    TNdstEntropyRateFile.write(trueNegatives_r)
        
    TPdstEntropyFile.close()
    TPdstEntropyRateFile.close()
    FPdstEntropyFile.close()
    FPdstEntropyRateFile.close()
    FNdstEntropyFile.close()
    FNdstEntropyRateFile.close()
    TNdstEntropyFile.close()
    TNdstEntropyRateFile.close()


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

detectionDst(silkFile, start, stop, systemId, frequency, interval, windowSize, 0, 0, attackDate)