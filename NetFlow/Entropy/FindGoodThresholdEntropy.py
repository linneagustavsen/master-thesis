

from datetime import datetime, timedelta
from pathlib import Path
import numpy as np
import pandas as pd


def findGoodThresholdEntropy(y_field, systemId, interval, windowSize, attackDate):
    p = Path('ThresholdDecision')
    decisionPath = p / 'Entropy' / 'NetFlow'
    if attackDate == "08.03.23":
        fileString = "0803"
        q = decisionPath /'Attack0803'
    elif attackDate == "17.03.23":
        fileString = "1703"
        q = decisionPath /'Attack1703'
    elif attackDate == "24.03.23":
        fileString = "2403"
        q = decisionPath /'Attack2403'
    if not q.exists():
        q.mkdir(parents=True)
    
    data = pd.read_csv("Calculations"+fileString+"/Entropy/NetFlow/Metrics."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    sTime = pd.to_datetime(data["sTime"])
    eTime = pd.to_datetime(data["eTime"])

    metricCalc = data[y_field]
    
    attackFlows = pd.read_csv("Calculations"+fileString+"/Entropy/NetFlow/AttackFlows.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
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

    changeDict = {}
    maxChange = 0
    minChange = 100000000000000000
    isThereAttack = False
    changeList = []
    for i in range(len(metricCalc)):
        sTime[i] = sTime[i].replace(tzinfo=None)
        eTime[i] = eTime[i].replace(tzinfo=None)

        attack = False
        for timeInterval in attackIntervals:
            if sTime[i] in timeInterval or eTime[i] in timeInterval:
                attack = True
                isThereAttack = True
        
        if i >=windowSize:
            change = abs(metricCalc[i] - np.nanmean(metricCalc[i-windowSize: i-1]))
            if change == np.nan or change == None:
                if attack:
                    changeDict[str(i)]  = {"attack": attack, "change": None}
                continue
            if change > maxChange:
                maxChange = change
            if change < minChange:
                minChange = change
            changeDict[str(i)]  = {"attack": attack, "change": change}
            changeList.append(int(change*10000000000))
        elif attack:
            changeDict[str(i)]  = {"attack": attack, "change": None}
    
    if not isThereAttack:
        print("No attacks!!")
        return
    changeList = list(dict.fromkeys(changeList))
    thresholds = list(sorted(changeList))
    f_scores = open(str(q) + "/" + str(y_field) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_scores.write("Threshold,TP,FP,FN,TN,F1,TPR,FPR,Accuracy,FNR,PPV")

    lastTruePositives = 0
    lastFalsePositives = 0
    lastFalseNegatives = 0
    lastTrueNegatives = 0

    max_f1 = 0
    max_tpr = 0
    min_fpr = 1000
    max_accuracy = 0
    min_fnr = 1000
    max_ppv = 0

    threshold_f1 = 0
    threshold_tpr = 0
    threshold_fpr = 0
    threshold_accuracy = 0
    threshold_fnr = 0
    threshold_ppv = 0
    for threshold in thresholds:
        threshold = threshold/10000000000
        
        truePositives = 0
        falsePositives = 0
        falseNegatives = 0
        trueNegatives  = 0
        for key in changeDict:
            change = changeDict[key]["change"]
            attack = changeDict[key]["attack"]
            if change == None:
                if attack:
                    falseNegatives += 1
                else:
                    trueNegatives += 1
                continue
            if change > threshold:
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
        if falsePositives == 0 and trueNegatives == 0 and falsePositives == 0 and falseNegatives == 0:
            continue
        accuracy = (truePositives +trueNegatives)/(truePositives +trueNegatives + falsePositives + falseNegatives)
        if falsePositives != 0 or trueNegatives != 0:
            fpr = falsePositives/(falsePositives + trueNegatives)
        else:
            fpr = None
        if falseNegatives != 0  or truePositives != 0:
            fnr = falseNegatives/(falseNegatives + truePositives)
        else:
            fnr = None
        if truePositives != 0 or falsePositives != 0:
            ppv = truePositives/(truePositives+falsePositives)
        else:
            ppv = None
        if falseNegatives != 0 or truePositives != 0:
            tpr = truePositives/(truePositives+ falseNegatives)
        else:
            tpr = None
        if truePositives != 0 or falsePositives!= 0 or falseNegatives != 0:
            f1 =2*truePositives/(2*truePositives+falsePositives+falseNegatives)
        else:
            f1 = None

        f_scores.write("\n" + str(threshold) + "," + str(truePositives) + "," + str(falsePositives) + ","
                       + str(falseNegatives) + "," + str(trueNegatives) + "," + str(f1) +  "," + str(tpr) + ","+
                       str(fpr) + "," + str(accuracy) + "," + str(fnr) + ","+ str(ppv))
    f_scores.close()
        
systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
attackDates = ["17.03.23","24.03.23"]
y_fields = ["dstEntropy", "dstEntropyRate","srcEntropy", "srcEntropyRate", "flowEntropy", "flowEntropyRate", "numberOfFlows", "icmpRatio", 
            "icmpPackets", "packetSizeEntropy", "packetSizeEntropyRate", "numberOfPackets", "numberOfBytes"]
intervals = [timedelta(minutes = 5),timedelta(minutes = 10), timedelta(minutes = 15)]

for attackDate in attackDates:
    print(attackDate)
    for systemId in systems:
        print(systemId)
        for interval in intervals:
            print(interval)
            for y_field in y_fields:
                print(y_field)
                findGoodThresholdEntropy(y_field, systemId, interval, 10, attackDate)
