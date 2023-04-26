from pathlib import Path
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
    TPdstEntropyFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    TPdstEntropyRateFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open files to write alerts to
    FPdstEntropyFile = open(str(q) + "/FP.DestinationIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FPdstEntropyRateFile = open(str(q) + "/FP.DestinationIPEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    FPdstEntropyFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    FPdstEntropyRateFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open files to write alerts to
    FNdstEntropyFile = open(str(q) + "/FN.DestinationIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    FNdstEntropyRateFile = open(str(q) + "/FN.DestinationIPEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    FNdstEntropyFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    FNdstEntropyRateFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))

    #Open files to write alerts to
    TNdstEntropyFile = open(str(q) + "/TN.DestinationIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    TNdstEntropyRateFile = open(str(q) + "/TN.DestinationIPEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    TNdstEntropyFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    TNdstEntropyRateFile.write("sTime,eTime,Deviation_score,Change,Value,Mean_last_"+ str(windowSize))
    
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

    #Makes datetime objects of the input times
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    windowTime = startTime

    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    records = []

    ipDstArray = []
    ipDstRateArray = []

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
            #Find the probability distribution based on how many packets there is in each destination flow in this time interval
            PiDIP, nd = ipDestinationDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropyDip = generalizedEntropy(10,PiDIP)
            ipDstArray.append(entropyDip)
            #Calculate the generalized entropy rate of this distribution
            ipDstRateArray.append(entropyDip/nd)
            
            attack = isAttack(rec.stime - frequency, rec.stime)
            #If there is enough stored values to compare with we compare the difference of each metric with a threshold
            if i >=windowSize:
                
                change = ipDstArray[i] - np.nanmean(ipDstArray[i-windowSize: i-1])
                change_r = ipDstRateArray[i] - np.nanmean(ipDstRateArray[i-windowSize: i-1])
                if change < 0 and change_r < 0:
                    attackType = "Low-Rate"
                elif change_r < 0:
                    attackType = "Flooding"
                else:
                    attackType = ""

                simulateRealTime(datetime.now(), rec.stime, attackDate)
                if abs(change) > thresholdDstEntropy:
                    alert = {
                        "sTime": (rec.stime - frequency).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "Change": abs(change),
                        "Deviation_score": normalization(abs(change), maxmin_dip["minimum"], maxmin_dip["maximum"]),
                        "Value": ipDstArray[i],
                        "Mean_last_10": np.nanmean(ipDstArray[i-windowSize: i-1]),
                        "Real_label": int(attack),
                        "Attack_type": attackType
                        }
                    mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
                if abs(change_r) >  thresholdDstEntropyRate:
                    alert = {
                        "sTime": (rec.stime - frequency).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "eTime": rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Gateway": systemId,
                        "Change": abs(change_r),
                        "Deviation_score": normalization(abs(change_r), maxmin_dip_rate["minimum"], maxmin_dip_rate["maximum"]),
                        "Value": ipDstRateArray[i],
                        "Mean_last_10": np.nanmean(ipDstRateArray[i-windowSize: i-1]),
                        "Real_label": int(attack),
                        "Attack_type": attackType
                        }
                    mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
                
                line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(normalization(abs(change), maxmin_dip["minimum"], maxmin_dip["maximum"])) + ","+ str(abs(change)) + "," + str(ipDstArray[i]) + "," + str(np.nanmean(ipDstArray[i-windowSize: i-1]))
                if abs(change) > thresholdDstEntropy and attack:
                    TPdstEntropyFile.write(line)
                elif abs(change) > thresholdDstEntropy and not attack:
                    FPdstEntropyFile.write(line)
                elif abs(change) <= thresholdDstEntropy and attack:
                    FNdstEntropyFile.write(line)
                elif abs(change) <= thresholdDstEntropy and not attack:
                    TNdstEntropyFile.write(line)
                
                line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(normalization(abs(change_r), maxmin_dip_rate["minimum"], maxmin_dip_rate["maximum"])) + ","+ str(abs(change_r)) + "," + str(ipDstRateArray[i]) + "," + str(np.nanmean(ipDstRateArray[i-windowSize: i-1]))
                if abs(change_r) > thresholdDstEntropyRate and attack:
                    TPdstEntropyRateFile.write(line)
                elif abs(change_r) > thresholdDstEntropyRate and not attack:
                    FPdstEntropyRateFile.write(line)
                elif abs(change_r) <= thresholdDstEntropyRate and attack:
                    FNdstEntropyRateFile.write(line)
                elif abs(change_r) <= thresholdDstEntropyRate and not attack:
                    TNdstEntropyRateFile.write(line)
            else:
                line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ")
                if attack:
                    FNdstEntropyFile.write(line)
                    FNdstEntropyRateFile.write(line)
                elif not attack:
                    TNdstEntropyFile.write(line)
                    TNdstEntropyRateFile.write(line)
            #Push the sliding window
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1

        records.append(rec)
    
    TPdstEntropyFile.close()
    TPdstEntropyRateFile.close()
    FPdstEntropyFile.close()
    FPdstEntropyRateFile.close()
    FNdstEntropyFile.close()
    FNdstEntropyRateFile.close()
    TNdstEntropyFile.close()
    TNdstEntropyRateFile.close()
    
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

detectionDst(silkFile, start, stop, systemId, frequency, interval, windowSize, 0, 0, attackDate)