from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime,timedelta
import json

def topkflows(silkFile, start, stop, interval, k):
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
    
        #Aggregate flows into the specified time interval
        if rec.stime > startTime + interval:
            #Array to keep track of the probability distribution
            Pi = {}
            
            topk = dict(list(sorted(numberOfPacketsPerIP.items(), key=lambda item: item[1], reverse=True))[:k])

            #Loop through each IP flow in the time interval
            for key, value in topk.items():
                #Add the probability of the current destination flow having the size that it does to the distribution
                Pi[str(key)] = value


            distributions.append(Pi)
            numberOfPacketsPerIP ={}
            sumOfPackets = 0
            startTime = startTime + interval
    
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

def topkflows2(silkFile, start, stop, interval, k, attackDate, systemId):
    f = open("Detections/TopKFlows/NetFlow/TopFlowChange."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f.write("Time,Position,Packets,Percentage")
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
    
        #Aggregate flows into the specified time interval
        if rec.stime > startTime + interval:
            #Array to keep track of the probability distribution
            Pi = []
            
            topk = dict(list(sorted(numberOfPacketsPerIP.items(), key=lambda item: item[1], reverse=True))[:k])

            if notTheFirstTime:
                lastDistribution = distributions[-1]
        
            change = False
            i = 0
            #Loop through each IP flow in the time interval
            for key, value in topk.items():
                exists = False
                if notTheFirstTime:
                    for j in range(len(lastDistribution)):
                        if str(key) == lastDistribution[j][0]:
                            exists = True
                    if not exists: # and (value/sumOfPackets) >= 0.01:
                        #print(i+1, str(key), value, (value/sumOfPackets))
                        f.write("\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(i+1)+ "," + str(value) + "," + str((value/sumOfPackets)))
                        change = True
                    if change:
                        print(str(startTime))
                        print("-----------------------------------------------------------------------------------------------------")
                        change = False
                #Add the probability of the current destination flow having the size that it does to the distribution
                Pi.append((str(key), value, value/sumOfPackets))

                i+=1

            distributions.append(Pi)
            numberOfPacketsPerIP ={}
            sumOfPackets = 0
            startTime = startTime + interval
            notTheFirstTime = True
    
        #If the current flow has the same destination IP as a previous flow the number of packets is added to the record of that destination IP
        #If it has not been encountered before it is added to the dictionary
        if rec.dip in numberOfPacketsPerIP:
            numberOfPacketsPerIP[rec.dip] += rec.packets
        else:
            numberOfPacketsPerIP[rec.dip] = rec.packets
        sumOfPackets += rec.packets
    