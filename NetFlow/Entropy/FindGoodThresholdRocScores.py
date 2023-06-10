

from datetime import datetime, timedelta
from pathlib import Path
import numpy as np
import pandas as pd


def findGoodThresholdEntropy(y_field_name, y_field, alpha, systemId, frequency, interval, windowSize, attackDate):
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
    
    data = pd.read_csv("FindBestRocScore/Calculations/Entropy/NetFlow/" + str(y_field_name) +".alpha."+ str(alpha)+ ".windowSize."+ str(windowSize)+ "."+ str(int(frequency.total_seconds()))+ "secFrequency." +str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    labels = data["real_label"]

    changes = pd.to_numeric(data["Change"],errors='coerce')
    changeList = list(changes.dropna())
    newChangeList = [i * 10000000000 for i in changeList]
    thresholds = list(sorted(newChangeList))
    f_scores = open(str(q) + "/RocScores/" + str(y_field) +".alpha."+ str(alpha)+ ".windowSize."+ str(windowSize)+ "."+ str(int(frequency.total_seconds()))+ "secFrequency." +str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_scores.write("Threshold,TP,FP,FN,TN,F1,TPR,FPR,Accuracy,FNR,PPV")

    lastTruePositives = 0
    lastFalsePositives = 0
    lastFalseNegatives = 0
    lastTrueNegatives = 0
    for threshold in thresholds:
        threshold = threshold/10000000000
        
        truePositives = 0
        falsePositives = 0
        falseNegatives = 0
        trueNegatives  = 0
        for i in range(len(changes)):
            change = changes[i]
            attack = labels[i]
            if change == None:
                if attack:
                    falseNegatives += 1
                else:
                    trueNegatives += 1
                continue
            #print(change, threshold)
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
            break
        if lastTruePositives == truePositives and lastFalsePositives == falsePositives and lastFalseNegatives == falseNegatives and lastTrueNegatives == trueNegatives:
            continue
        else:
            lastTruePositives = truePositives
            lastFalsePositives = falsePositives
            lastFalseNegatives = falseNegatives
            lastTrueNegatives = trueNegatives
        if trueNegatives != 0 and falsePositives != 0 and falseNegatives != 0:
            accuracy = (truePositives +trueNegatives)/(truePositives +trueNegatives + falsePositives + falseNegatives)
        else:
            accuracy = None
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
        
systemId = "hoytek-gw2"
attackDate="24.03.23"
y_fields = ["dstEntropy", "dstEntropyRate","srcEntropy", "srcEntropyRate", "flowEntropy", "flowEntropyRate", "numberOfFlows", "icmpRatio", 
            "icmpPackets", "packetSizeEntropy", "packetSizeEntropyRate", "numberOfPackets", "numberOfBytes"]
y_field_names = ["DestinationIPEntropy", "DestinationIPEntropyRate","SourceIPEntropy", "SourceIPEntropyRate", "FlowEntropy", "FlowEntropyRate", "NumberOfFlows", "ICMPRatio", 
            "ICMPPackets", "PacketSizeEntropy", "PacketSizeEntropyRate", "Packets", "Bytes"]

frequencies = [timedelta(seconds=5),timedelta(seconds=10), timedelta(seconds=20), timedelta(seconds=30), timedelta(seconds=40), timedelta(seconds=50),timedelta(minutes=1)]
for frequency in frequencies:
    for i in range(1,21):
        interval = timedelta(minutes=i)
        for alpha in range(2, 16):
            for windowSize in range(2,21):
                for k in range(len(y_fields)):
                    if alpha == 2:
                        continue
                    print("frequency")
                    print(frequency)
                    print("interval")
                    print(i)
                    print("alpha")
                    print(alpha)
                    print("Window size")
                    print(windowSize)
                    print("y_field")
                    print(y_fields[k])
                    print("\n")
                    findGoodThresholdEntropy(y_field_names[k], y_fields[k], alpha, systemId, frequency, interval, windowSize, attackDate)
                    