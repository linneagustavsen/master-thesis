from pathlib import Path
from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime,timedelta
import json
import paho.mqtt.client as mqtt
from HelperFunctions.IsAttack import isAttack
from HelperFunctions.Normalization import normalization
from HelperFunctions.SimulateRealTime import simulateRealTime


def topkflows(silkFile, start, stop, frequency, k, attackDate, systemId):
    p = Path('Detections')
    q = p / 'TopKFlows' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)

    #Open file to write alerts to
    TPfile = open(str(q) + "/TP.TopKFlows.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    TPfile.write("sTime,eTime,Deviation_score,Change,Value,Packets,Percentage")

    #Open file to write alerts to
    FPfile = open(str(q) + "/FP.TopKFlows.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    FPfile.write("sTime,eTime,Deviation_score,Change,Value,Packets,Percentage")

    #Open file to write alerts to
    FNfile = open(str(q) + "/FN.TopKFlows.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    FNfile.write("sTime,eTime,Deviation_score,Change,Value,Packets,Percentage")

    #Open file to write alerts to
    TNfile = open(str(q) + "/TN.TopKFlows.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")

    #Write the column titles to the files
    TNfile.write("sTime,eTime,Deviation_score,Change,Value,Packets,Percentage")

    #Parameters for the MQTT connection
    MQTT_BROKER = 'localhost'
    MQTT_PORT = 1883
    MQTT_USER = 'topkFlowsDetectionNetFlow'
    MQTT_PASSWORD = 'topKflowsDetectionPass'
    MQTT_TOPIC = 'detections/modules/netflow'

    #Function that is called when the sensor is connected to the MQTT broker
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("Top k flows detection published to topic", MQTT_TOPIC)

    #Connects to the MQTT broker with password and username
    mqtt_client = mqtt.Client("TopKFlowsDetectionNetFlow")
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    mqtt_client.on_publish = on_publish
    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT)

    #Makes a datetime object of the input start time
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    distributions = []
    #Make dictionaries for how many packets each destination flow has
    numberOfPacketsPerIP ={}
    sumOfPackets = 0
    notTheFirstTime = False
    #Loop through all the flow records in the input file
    for rec in infile:
        if rec.etime >= stopTime:
            break
        if rec.stime < startTime:
            continue
    
        #Aggregate flows into the specified time frequency
        if rec.stime > startTime + frequency:
            #Array to keep track of the probability distribution
            Pi = []
            
            topk = dict(list(sorted(numberOfPacketsPerIP.items(), key=lambda item: item[1], reverse=True))[:k])

            if notTheFirstTime:
                lastDistribution = distributions[-1]
        
            change = False
            i = 0
            #Loop through each IP flow in the time frequency
            for key, value in topk.items():
                attack = isAttack(rec.stime - frequency, rec.stime)
                exists = False
                if notTheFirstTime:
                    for j in range(len(lastDistribution)):
                        if str(key) == lastDistribution[j][0]:
                            exists = True
                    if not exists:
                        change = True
                        simulateRealTime(datetime.now(), rec.stime, attackDate)
                        alert = {
                            "sTime": (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "eTime": rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "Gateway": systemId,
                            "Deviation_score": normalization(20-i, 0, 20),
                            "srcIP": int(rec.sip),
                            "dstIP": int(rec.dip),
                            "srcPort": rec.sport,
                            "dstPort": rec.dport,
                            "protocol": rec.protocol,
                            "Position": i+1,
                            "Packets": value,
                            "Percentage": value/sumOfPackets,
                            "Real_label": int(attack),
                            "Attack_type": "Flooding"
                        }
                        mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
                    
                    line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(normalization(20-i,0, 20)) + ","+ str(20-i) + "," + str(i+1) + "," + str(value) + "," + str(value/sumOfPackets)
                    if not exists and attack:
                        TPfile.write(line)
                    elif not exists and not attack:
                        FPfile.write(line)
                    elif exists and attack:
                        FNfile.write(line)
                    elif exists and not attack:
                        TNfile.write(line)

                    if change:
                        change = False
                else:
                    line = "\n" + (rec.stime- frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," +  rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ")
                    if attack:
                        FNfile.write(line)
                    elif not attack:
                        TNfile.write(line)
                #Add the probability of the current destination flow having the size that it does to the distribution
                Pi.append((str(key), value, value/sumOfPackets))

                i+=1

            distributions.append(Pi)
            numberOfPacketsPerIP ={}
            sumOfPackets = 0
            startTime = startTime + frequency
            notTheFirstTime = True
    
        #If the current flow has the same destination IP as a previous flow the number of packets is added to the record of that destination IP
        #If it has not been encountered before it is added to the dictionary
        if rec.dip in numberOfPacketsPerIP:
            numberOfPacketsPerIP[rec.dip] += rec.packets
        else:
            numberOfPacketsPerIP[rec.dip] = rec.packets
        sumOfPackets += rec.packets
    TPfile.close()
    FPfile.close()
    FNfile.close()
    TNfile.close()


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
topkflows(silkFile, start, stop, frequency, 20, attackDate, systemId)