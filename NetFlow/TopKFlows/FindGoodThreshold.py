

from datetime import datetime, timedelta
from pathlib import Path
import numpy as np
import pandas as pd


def findGoodThreshold(systemId, attackDate):
    p = Path('ThresholdDecision')
    decisionPath = p / 'TopKFlows' / 'NetFlow'
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
    
    f_scores = open(str(q) + "/TopKFlows.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_scores.write("Threshold,TP,FP,FN,TN,F1,TPR,FPR,Accuracy,FNR,PPV")
    data = pd.read_csv("Calculations"+fileString+"/TopKFlows/NetFlow/TopFlowChange.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    sTime = pd.to_datetime(data["sTime"])
    eTime = pd.to_datetime(data["eTime"])
    label = data["real_label"]

    changeInPosition = data["Change"]

    for threshold in range(0,100):
        threshold = threshold/100
        truePositives = 0
        falsePositives = 0
        falseNegatives = 0
        trueNegatives  = 0
        for i in range(len(changeInPosition)):
            sTime[i] = sTime[i].replace(tzinfo=None)
            eTime[i] = eTime[i].replace(tzinfo=None)

            if changeInPosition[i] > threshold:
                if label[i]:
                    truePositives += 1
                else:
                    falsePositives += 1
            else:
                if label[i]:
                    falseNegatives += 1
                else:
                    trueNegatives += 1
        if trueNegatives == 0 and falsePositives == 0 and falseNegatives == 0:
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
attackDates = ["08.03.23","17.03.23", "24.03.23"]
print("Top K flows")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for systemId in systems:
        print(systemId)
        findGoodThreshold(systemId, attackDate)
