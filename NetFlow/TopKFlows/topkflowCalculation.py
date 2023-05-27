from pathlib import Path
from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime,timedelta
import json
from HelperFunctions.IsAttack import isAttack, isAttackFlow
from HelperFunctions.Normalization import normalization

def topkflows2(silkFile, start, stop, frequency, k, attackDate, systemId):
    p = Path('Calculations')
    q = p / 'TopKFlows' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    ipP = Path('IPCalculations')
    ipPath = ipP / 'Threshold'
    if not ipPath.exists():
        ipPath.mkdir(parents=True, exist_ok=False)
    f = open(str(ipPath) + "/TopFlowChange.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f.write("sTime,eTime,srcIP,dstIP,deviation_score,real_label")
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
                attack = isAttackFlow(rec.sip, rec.dip, rec.stime, rec.etime)
                exists = False
                if notTheFirstTime:
                    for j in range(len(lastDistribution)):
                        if str(key) == lastDistribution[j][0]:
                            exists = True
                    
                    if not exists: # and (value/sumOfPackets) >= 0.01:
                        f.write("\n" + (rec.stime-frequency).strftime("%Y-%m-%dT%H:%M:%SZ") + "," + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ")+ "," + 
                                str(rec.sip) + "," +str(rec.dip) + ","+ str(normalization(20-i, 0, 20)) + "," + str(int(attack)))
                        change = True
                        if attack:
                            truePositives += 1
                        else:
                            falsePositives += 1
                    else:
                        if attack:
                            falseNegatives += 1
                        else:
                            trueNegatives += 1

                    if change:
                        change = False
                else:
                    if attack:
                        falseNegatives += 1
                    else:
                        trueNegatives += 1
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

    f_scores = open(str(q) + "/Scores.TopKFlows.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_scores.write("TP,FP,FN,TN")
    f_scores.write("\n"+str(truePositives) + "," + str(falsePositives) + "," + str(falseNegatives) + "," + str(trueNegatives))
    f_scores.close()