from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime,timedelta
import json
import json
import paho.mqtt.client as mqtt

from HelperFunctions.IsAttack import isAttack
from HelperFunctions.Normalization import normalization

def topkflows(silkFile, start, stop, frequency, k):
    #Makes a datetime object of the input start time
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    distributions = []
    #Make dictionaries for how many packets each destination flow has
    numberOfPacketsPerIP ={}
    sumOfPackets = 0
    #Loop through all the flow records in the input file
    for rec in infile:
        if rec.etime >= stopTime:
            break
        if rec.stime < startTime:
            continue
    
        #Aggregate flows into the specified time frequency
        if rec.stime > startTime + frequency:
            #Array to keep track of the probability distribution
            Pi = {}
            
            topk = dict(list(sorted(numberOfPacketsPerIP.items(), key=lambda item: item[1], reverse=True))[:k])

            #Loop through each IP flow in the time frequency
            for key, value in topk.items():
                #Add the probability of the current destination flow having the size that it does to the distribution
                Pi[str(key)] = value


            distributions.append(Pi)
            numberOfPacketsPerIP ={}
            sumOfPackets = 0
            startTime = startTime + frequency
    
        #If the current flow has the same destination IP as a previous flow the number of packets is added to the record of that destination IP
        #If it has not been encountered before it is added to the dictionary
        if rec.dip in numberOfPacketsPerIP:
            numberOfPacketsPerIP[rec.dip] += rec.packets
        else:
            numberOfPacketsPerIP[rec.dip] = rec.packets
        sumOfPackets += rec.packets
    

    infile.close()
    json_file = open("NetFlow/TopKFlows/Calculations/topKflowsDict.json", "w")
    json.dump(distributions,json_file)
    json_file.close()

def topkflows2(silkFile, start, stop, frequency, k, attackDate, systemId):
    f = open("Calculations/TopKFlows/NetFlow/TopFlowChange.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f.write("Time,Position,Packets,Percentage")

    #Parameters for the MQTT connection
    MQTT_BROKER = 'mosquitto'
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
                exists = False
                if notTheFirstTime:
                    for j in range(len(lastDistribution)):
                        if str(key) == lastDistribution[j][0]:
                            exists = True
                    if not exists: # and (value/sumOfPackets) >= 0.01:
                        f.write("\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(i+1)+ "," + str(value) + "," + str((value/sumOfPackets)))
                        change = True
                        alert = {
                            "sTime": rec.stime- frequency,
                            "eTime": rec.stime,
                            "Gateway": systemId,
                            "Deviation_score": normalization(20-i, 0, 20),
                            "Position": i+1,
                            "Packets": value,
                            "Percentage": value/sumOfPackets,
                            "Real_label": int(isAttack(startTime)),
                            "Attack_type": "Flooding"
                        }
                        mqtt_client.publish(MQTT_TOPIC,json.dumps(alert))
                    if change:
                        change = False
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
    