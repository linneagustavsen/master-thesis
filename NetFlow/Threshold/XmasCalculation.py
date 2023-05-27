from pathlib import Path
from silk import *
from datetime import datetime
from HelperFunctions.IsAttack import *

'''
    Calculates the number of SYN packets in a flow and writes all values over 1 to file
    Input:  silkFile:   string, file with flow records sorted on time
            start:      string, start time of detection 
            stop:       string, stop time of detection 
            systemId:   string, name of the system to calculate on
            attackDate: string, date of the attack the calculations are made on
'''
def xmasCalculation(silkFile, start, stop, systemId, attackDate):
    p = Path('Calculations')
    q = p / 'Threshold' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    ipP = Path('IPCalculations')
    ipPath = ipP / 'Threshold'
    if not ipPath.exists():
        ipPath.mkdir(parents=True, exist_ok=False)
    #Open file to write alerts to
    #Open file to write alerts to
    calculations = open(str(ipPath) + "/Xmas.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #Write the column titles to the files
    calculations.write("sTime,eTime,srcIP,dstIP,real_label")
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')

    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate variables
    i = 0
    truePositives = 0
    falsePositives = 0
    falseNegatives = 0
    trueNegatives = 0

    #Loop through all the flow records
    for rec in infile:
        if rec.etime > stopTime:
            continue
        if rec.stime < startTime:
            continue

        attack = isAttackFlow(rec.sip, rec.dip, rec.stime, rec.etime) 
        if rec.tcpflags.urg and rec.tcpflags.psh and rec.tcpflags.fin:
            calculations.write("\n" + rec.stime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + rec.etime.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + 
                                str(rec.sip) + "," +str(rec.dip) + ","+ str(int(attack)))
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

    f_scores = open(str(q) + "/Scores.Xmas.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_scores.write("TP,FP,FN,TN")
    f_scores.write("\n"+str(truePositives) + "," + str(falsePositives) + "," + str(falseNegatives) + "," + str(trueNegatives))
    f_scores.close()

