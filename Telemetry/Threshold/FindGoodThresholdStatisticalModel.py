

from datetime import datetime, timedelta
from pathlib import Path
import numpy as np
import pandas as pd


def findGoodThresholdStatisticalModel(y_field, systemId, attackDate):
    p = Path('ThresholdDecision')
    q = p / 'Threshold' / 'Telemetry'
    if not q.exists():
        q.mkdir(parents=True)
    data = pd.read_csv("Calculations0803/Threshold/Telemetry/" + str(y_field)+".attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    metricCalc = data["Deviation_score"]
    
    labels = data["real_label"]
    if 1 not in labels:
        print("No attack")
        return
    
    f_scores = open(str(q) + "/" + str(y_field)+".attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_scores.write("Threshold,TP,FP,FN,TN,F1,TPR,FPR,Accuracy,FNR,PPV")

    changeList = []
    for deviationScore in metricCalc:
        if pd.isnull(deviationScore):
            print("it is nan")
            continue
        changeList.append(int(deviationScore*1000))
    changeList = list(dict.fromkeys(changeList))
    thresholds = list(sorted(changeList))
    #print(thresholds)
    minChange = min(metricCalc)
    maxChange = max(metricCalc)
    print(minChange)
    print(maxChange)
    print(len(thresholds))
    for threshold in thresholds:
        threshold = threshold/1000
        truePositives = 0
        falsePositives = 0
        falseNegatives = 0
        trueNegatives  = 0

        for i in range(len(metricCalc)):
            change = metricCalc[i]
            attack = labels[i]
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
        
'''systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
attackDate="08.03.23"
y_fields= ["egress_stats__if_1sec_octets", "ingress_stats__if_1sec_pkts", "ingress_stats__if_1sec_octets", "MaxVar.egress_queue_info__0__cur_buffer_occupancy", "MaxVar.egress_stats__if_1sec_pkts", "MaxVar.egress_stats__if_1sec_octets", "MaxVar.ingress_stats__if_1sec_pkts", "MaxVar.ingress_stats__if_1sec_octets"]

for y_field in y_fields:
    print(y_field)
    if y_field =="egress_stats__if_1sec_octets":
        for systemId in ["ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", "oslo-gw1"]:
            findGoodThresholdStatisticalModel(y_field, systemId, attackDate)
    else:
        for systemId in systems:
            print(systemId) 
            findGoodThresholdStatisticalModel(y_field, systemId, attackDate)
'''