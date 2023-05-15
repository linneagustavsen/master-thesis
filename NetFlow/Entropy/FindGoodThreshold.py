

from datetime import datetime, timedelta
import pathlib
import numpy as np
import pandas as pd


def findGoodThreshold(y_field, systemId, interval, windowSize, attackDate):
    p = pathlib('ThresholdDecision')
    q = p / 'Entropy' / 'NetFlow'
    f_scores = open(str(q) + "/" + str(y_field) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_scores.write("Threshold,TP,FP,FN,TN,F1,TPR,FPR,Accuracy,FNR,PPV")
    data = pd.read_csv("Calculations0803/Entropy/NetFlow/Metrics."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    sTime = pd.to_datetime(data["sTime"])
    eTime = pd.to_datetime(data["eTime"])

    metricCalc = data[y_field]
    
    attackFlows = pd.read_csv("Calculations0803/Entropy/NetFlow/AttackFlows."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
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


    thresholds = [0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9,
                  1,1.1,1.2,1.3,1.4,1.5,1.6,1.7,1.8,1.9,
                  2,2.1,2.2,2.3,2.4,2.5,2.6,2.7,2.8,2.9,
                  3,3.1,3.2,3.3,3.4,3.5,3.6,3.7,3.8,3.9,
                  4,4.1,4.2,4.3,4.4,4.5,4.6,4.7,4.8,4.9,
                  5,5.1,5.2,5.3,5.4,5.5,5.6,5.7,5.8,5.9,
                  6,6.1,6.2,6.3,6.4,6.5,6.6,6.7,6.8,6.9,
                  7]
    for threshold in range(0,10,0.1):
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
        accuracy = (truePositives +trueNegatives)/(truePositives +trueNegatives + falsePositives + falseNegatives)
        fpr = falsePositives/(falsePositives + trueNegatives)
        fnr = falseNegatives/(falseNegatives + truePositives)
        ppv = truePositives/(truePositives+ falsePositives)
        tpr = truePositives/(truePositives + falseNegatives)
        f1 = 2*(ppv*tpr)/(ppv+tpr)
        f_scores.write("\n" + str(threshold) + "," + str(truePositives) + "," + str(falsePositives) + ","
                       + str(falseNegatives) + "," + str(trueNegatives) + "," + str(f1) +  "," + str(tpr) + ","+
                       str(fpr) + "," + str(accuracy) + "," + str(fnr) + ","+ str(ppv))
    f_scores.close()
        
systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
attackDate="08.03.23"
y_fields = ["dstEntropy", "dstEntropyRate","srcEntropy", "srcEntropyRate", "flowEntropy", "flowEntropyRate", "numberOfFlows", "icmpRatio", 
            "icmpPackets", "packetSizeEntropy", "packetSizeEntropyRate", "numberOfPackets", "numberOfBytes"]
intervals = [timedelta(minutes = 5), timedelta(minutes = 10), timedelta(minutes = 15)]
for systemId in systems:
    print(systemId)
    for interval in intervals:
        print(str(interval))
        for y_field in y_fields:
            print(y_field)
            findGoodThreshold(y_field, systemId, interval, 10, attackDate)