from pathlib import Path
from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime,timedelta
import json
from HelperFunctions.IsAttack import isAttack, isAttackFlow
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
        if rec.etime > stopTime + frequency:
            continue
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
    p = Path('NetFlow')
    q = p / 'TopKFlows' / 'Calculations'
    if not q.exists():
        q.mkdir(parents=True)
    json_file = open(str(q) + "/topKflowsDict.json", "w")
    json.dump(distributions,json_file)
    json_file.close()

def topkflows2(silkFile, start, stop, frequency, k, attackDate, systemId):
    p = Path('Calculations')
    q = p / 'TopKFlows' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    f = open(str(q) + "/TopFlowChange.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #f.write("sTime,eTime,Change,Position,Packets,Percentage,srcPort,dstPort,protocol,real_label")
    f.write("sTime,eTime,Change,real_label")
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
        if rec.etime > stopTime + frequency:
            continue
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
                        '''f.write("\n" + (rec.stime-frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + 
                                str(normalization(20-i, 0, 20)) + ","+  str(i+1)+ "," + str(value) + "," + str((value/sumOfPackets))+  "," +
                                str(rec.sport) + "," + str(rec.dport) + "," + str(rec.protocol) + "," + str(isAttackFlow(rec.sip, rec.dip, rec.stime, rec.etime)))'''
                        f.write("\n" + (rec.stime-frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + 
                                str(normalization(20-i, 0, 20)) + ","+  str(isAttackFlow(rec.sip, rec.dip, rec.stime, rec.etime)))
                        change = True

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
        if int(rec.dip) in numberOfPacketsPerIP:
            numberOfPacketsPerIP[int(rec.dip)] += rec.packets
        else:
            numberOfPacketsPerIP[int(rec.dip)] = rec.packets
        sumOfPackets += rec.packets
    f.close()