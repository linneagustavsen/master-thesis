

from datetime import datetime, timedelta
from pathlib import Path
import numpy as np
import pandas as pd


def findGoodThresholdEntropy(y_field, systemId, interval, windowSize, attackDate):
    p = Path('ThresholdDecision')
    q = p / 'Entropy' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    f_scores = open(str(q) + "/" + str(y_field) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_scores.write("Threshold,TP,FP,FN,TN,F1,TPR,FPR,Accuracy,FNR,PPV")
    data = pd.read_csv("Calculations0803/Threshold/NetFlow/ICMPDstUnreachable."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    sTime = pd.to_datetime(data["sTime"])
    eTime = pd.to_datetime(data["eTime"])

    metricCalc = data[y_field]
    
    attackFlows = pd.read_csv("Calculations0803/Entropy/NetFlow/AttackFlows.ICMPDstUnreachable"+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
    sTimeAttacks = pd.to_datetime(attackFlows["sTime"])
    eTimeAttacks = pd.to_datetime(attackFlows["eTime"])
   
    attackIntervals = []
    
    lastInterval = pd.Interval(pd.Timestamp.now().replace(tzinfo=None), pd.Timestamp.now().replace(tzinfo=None), closed="both")
    for i in range(len(sTimeAttacks)):
        if sTimeAttacks[i].replace(second=0).replace(tzinfo=None) in lastInterval and eTimeAttacks[i].replace(second=0).replace(tzinfo=None) in lastInterval:
            continue
        elif sTimeAttacks[i].replace(second=0).replace(tzinfo=None) in lastInterval:
            attackIntervals.remove(lastInterval)
            lastInterval = pd.Interval(lastInterval.left, eTimeAttacks[i].replace(second=0).replace(tzinfo=None), closed="both")
            attackIntervals.append(lastInterval)
        
        elif eTimeAttacks[i].replace(second=0).replace(tzinfo=None) in lastInterval:
            attackIntervals.remove(lastInterval)
            lastInterval = pd.Interval(sTimeAttacks[i].replace(second=0).replace(tzinfo=None), lastInterval.right, closed="both")
            attackIntervals.append(lastInterval)
        else:
            lastInterval = pd.Interval(sTimeAttacks[i].replace(second=0).replace(tzinfo=None), eTimeAttacks[i].replace(second=0).replace(tzinfo=None), closed="both")
            attackIntervals.append(lastInterval)

    for threshold in range(0,4000):
        #threshold = threshold/100
        #print(threshold)
        
        truePositives = 0
        falsePositives = 0
        falseNegatives = 0
        trueNegatives  = 0
        for i in range(len(metricCalc)):
            sTime[i] = sTime[i].replace(tzinfo=None)
            eTime[i] = eTime[i].replace(tzinfo=None)

            attack = False
            for timeInterval in attackIntervals:
                if sTime[i] in timeInterval or eTime[i] in timeInterval:
                    attack = True
            if i >=windowSize:

                
                change = metricCalc[i] - np.nanmean(metricCalc[i-windowSize: i-1])
                
                if abs(change) > threshold:
                    if attack:
                        truePositives += 1
                    else:
                        falsePositives += 1
                else:
                    if attack:
                        falseNegatives += 1
                    else:
                        trueNegatives += 1
        if truePositives == 0:
            continue
        elif trueNegatives == 0 and falsePositives == 0 and falseNegatives == 0:
            continue
        accuracy = (truePositives +trueNegatives)/(truePositives +trueNegatives + falsePositives + falseNegatives)
        if not falsePositives == 0 and not trueNegatives == 0:
            fpr = falsePositives/(falsePositives + trueNegatives)
        else:
            fpr = None
        if not falseNegatives == 0  and not truePositives == 0:
            fnr = falseNegatives/(falseNegatives + truePositives)
        else:
            fnr = None
        if not truePositives == 0 and not falsePositives == 0:
            ppv = truePositives/(truePositives+ falsePositives)
        else:
           ppv = None
        if not falseNegatives == 0  and not truePositives == 0:
            tpr = truePositives/(truePositives + falseNegatives)
        else:
            tpr = None
        if not truePositives == 0 and not falsePositives== 0 and not falseNegatives == 0:
            f1 = 2*(ppv*tpr)/(ppv+tpr)
        else:
            f1 = None
        f_scores.write("\n" + str(threshold) + "," + str(truePositives) + "," + str(falsePositives) + ","
                       + str(falseNegatives) + "," + str(trueNegatives) + "," + str(f1) +  "," + str(tpr) + ","+
                       str(fpr) + "," + str(accuracy) + "," + str(fnr) + ","+ str(ppv))
    f_scores.close()
        
systems = ["teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
attackDate="08.03.23"
y_fields = ["ICMPDstUnreachable"]
intervals = [timedelta(minutes = 10)]
for systemId in systems:
    print(systemId)
    for interval in intervals:
        print(str(interval))
        for y_field in y_fields:
            print(y_field)
            findGoodThresholdEntropy(y_field, systemId, interval, 10, attackDate)
