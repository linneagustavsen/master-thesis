

from datetime import datetime, timedelta
from pathlib import Path
import numpy as np
import pandas as pd


def findGoodThresholdEntropy(y_field, systemId, interval, windowSize, attackDate):
    p = Path('ThresholdDecision')
    q = p / 'Threshold' / 'Telemetry'
    if not q.exists():
        q.mkdir(parents=True)
    data = pd.read_csv("Calculations0803/Threshold/Telemetry/" + str(y_field)+".attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    sTime = pd.to_datetime(data["sTime"])
    eTime = pd.to_datetime(data["eTime"])

    metricCalc = data["Deviation_score"]
    
    labels = data["real_label"]
    if 1 not in labels:
        print("No attack")
        return
    
    f_scores = open(str(q) + "/" + str(y_field)+".attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_scores.write("Threshold,TP,FP,FN,TN,F1,TPR,FPR,Accuracy,FNR,PPV")
    
    changeDict = {}
    maxChange = 0
    minChange = 100000000000000000
    changeList = []
    for i in range(len(metricCalc)):
        sTime[i] = sTime[i].replace(tzinfo=None)
        eTime[i] = eTime[i].replace(tzinfo=None)

        attack = labels[i]
        if i >=windowSize:
            change = abs(metricCalc[i] - np.nanmean(metricCalc[i-windowSize: i-1]))
            print(change)

            if change > maxChange:
                maxChange = change
            if change < minChange:
                minChange = change
            changeDict[str(i)]  = {"attack": attack, "change": change}
            changeList.append(int(change*1000000))
        elif attack:
            changeDict[str(i)]  = {"attack": attack, "change": None}
            changeList.append(None)  
    changeList = list(dict.fromkeys(changeList))
    thresholds = list(sorted(changeList))

    print(minChange)
    print(maxChange)
    for threshold in thresholds:
        threshold = threshold/1000000
        truePositives = 0
        falsePositives = 0
        falseNegatives = 0
        trueNegatives  = 0

        for key in changeDict:
            change = changeDict[key]["change"]
            attack = changeDict[key]["attack"]
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
        
systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
attackDate="08.03.23"
y_fields= ["egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets", "ingress_stats__if_1sec_pkts", "ingress_stats__if_1sec_octets", "MaxVar.egress_queue_info__0__cur_buffer_occupancy", "MaxVar.egress_stats__if_1sec_pkts", "MaxVar.egress_stats__if_1sec_octets", "MaxVar.ingress_stats__if_1sec_pkts", "MaxVar.ingress_stats__if_1sec_octets"]
intervals = [timedelta(minutes = 5),timedelta(minutes = 10), timedelta(minutes = 15)]
for y_field in y_fields:
    print(y_field)
    for systemId in systems:
        print(systemId) 
        findGoodThresholdEntropy(y_field, systemId, 0, 10, attackDate)
