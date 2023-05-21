

from datetime import datetime
from  pathlib import Path
import numpy as np
import pandas as pd


def findGoodThreshold(systemId, attackDate):
    p = Path('ThresholdDecision')
    q = p / 'Threshold' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    f_scores = open(str(q) + "/SYN.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_scores.write("Threshold,TP,FP,FN,TN,F1,TPR,FPR,Accuracy,FNR,PPV")
    data = pd.read_csv("Calculations0803/Threshold/NetFlow/SYN.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    sTime = pd.to_datetime(data["sTime"])
    eTime = pd.to_datetime(data["eTime"])
    label = data["real_label"]

    synPacketsPerFlow = data["synPacketsPerFlow"]

    for threshold in range(0,100):
        truePositives = 0
        falsePositives = 0
        falseNegatives = 0
        trueNegatives  = 0
        for i in range(len(synPacketsPerFlow)):
            sTime[i] = sTime[i].replace(tzinfo=None)
            eTime[i] = eTime[i].replace(tzinfo=None)

            if synPacketsPerFlow[i] > threshold:
                if label[i]:
                    truePositives += 1
                else:
                    falsePositives += 1
            else:
                if label[i]:
                    falseNegatives += 1
                else:
                    trueNegatives += 1
        if falsePositives == 0 and trueNegatives == 0 and falsePositives == 0 and falseNegatives == 0:
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

systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
attackDate="08.03.23"
for systemId in systems:
    print(systemId)
    findGoodThreshold(systemId, attackDate)
