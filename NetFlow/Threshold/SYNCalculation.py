import json
from pathlib import Path
import numpy as np
from silk import *
from datetime import datetime
from HelperFunctions.IsAttack import *
from HelperFunctions.Normalization import normalization

'''
    Calculates the number of SYN packets in a flow and writes all values over 1 to file
    Input:  silkFile:   string, file with flow records sorted on time
            start:      string, start time of detection 
            stop:       string, stop time of detection 
            systemId:   string, name of the system to calculate on
            attackDate: string, date of the attack the calculations are made on
'''
def synCalculation(silkFile, start, stop, systemId, attackDate):
    p = Path('Calculations')
    q = p / 'Threshold' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    ipP = Path('IPCalculations')
    ipPath = ipP / 'Threshold'
    if not ipPath.exists():
        ipPath.mkdir(parents=True, exist_ok=False)
    #Open file to write alerts to
    #Open file to write alerts to
    calculations = open(str(ipPath) + "/SYN.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #Write the column titles to the files
    calculations.write("sTime,eTime,srcIP,dstIP,synPacketsPerFlow,deviation_score,real_label")
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    maxmin_syn = {"minimum": 0.0, "maximum": 0.01999320059119028}
    truePositives = 0
    falsePositives = 0
    falseNegatives = 0
    trueNegatives = 0

    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    synPacketsPerFlow = []
    
    #Instantiate variables
    i = 0

    #Loop through all the flow records
    for rec in infile:
        if rec.etime > stopTime:
            continue
        if rec.stime < startTime:
            continue
        synPacketsPerFlow.append(rec.packets)
        attack =  isAttackFlow(rec.sip, rec.dip, rec.stime, rec.etime)
        if rec.packets >= 3:
            if i >= 10:
                change = synPacketsPerFlow[i] - np.nanmean(synPacketsPerFlow[i-10: i-1])
                deviation = normalization(abs(change), maxmin_syn["minimum"], maxmin_syn["maximum"])
                calculations.write("\n"+ rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + rec.etime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(rec.sip) + "," +str(rec.dip) + ","+ str(synPacketsPerFlow[i])+ "," + str(deviation) +  "," +str(int(attack)))
            else:
                calculations.write("\n"+ rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + rec.etime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(rec.sip) + "," +str(rec.dip) + ","+ str(synPacketsPerFlow[i])+  "," + str(None) +  ","+ str(int(attack)))
            if attack:
                truePositives += 1
            else:
                falsePositives += 1
        else:
            if attack:
                falseNegatives += 1
            else:
                trueNegatives += 1
        i += 1
    infile.close()
    calculations.close()

    f_scores = open(str(q) + "/Scores.SYN.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_scores.write("TP,FP,FN,TN")
    f_scores.write("\n"+str(truePositives) + "," + str(falsePositives) + "," + str(falseNegatives) + "," + str(trueNegatives))
    f_scores.close()
