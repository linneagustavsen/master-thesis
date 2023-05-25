

from datetime import datetime, timedelta
from pathlib import Path
import numpy as np
import pandas as pd


def findGoodThresholdFromFile(y_field, systemId, interval, attackDate):
    p = Path('ThresholdDecision')
    q = p / 'Threshold' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True)
    f = open(str(q) + "/MinMax/Max_min_thresholds_Packets.txt", "a")

    data = pd.read_csv(str(q) + "/numberOfPackets."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")

    thresholds = pd.to_numeric(data["Threshold"],errors='coerce')
    f1_scores = pd.to_numeric(data["F1"],errors='coerce')
    tpr = pd.to_numeric(data["TPR"],errors='coerce')
    fpr = pd.to_numeric(data["FPR"],errors='coerce')
    accuracy = pd.to_numeric(data["Accuracy"],errors='coerce')
    fnr = pd.to_numeric(data["FNR"],errors='coerce')
    ppv = pd.to_numeric(data["PPV"],errors='coerce')
    tp = pd.to_numeric(data["TP"], errors='coerce')

    max_f1 = 0
    max_tpr = 0
    min_fpr = 1000
    max_accuracy = 0
    min_fnr = 1000
    max_ppv = 0

    index_f1 = 0
    index_tpr = 0
    index_fpr = 0
    index_accuracy = 0
    index_fnr = 0
    index_ppv = 0
    counter = 0

    for i in range(len(thresholds)):
        if tp[i] == 0:
            continue
        if f1_scores[i] > max_f1 and f1_scores[i] != np.nan:
            max_f1 = f1_scores[i]
            index_f1 = i

        if tpr[i] > max_tpr and tpr[i] != np.nan:
            max_tpr = tpr[i]
            index_tpr = i

        if fpr[i] > min_fpr and fpr[i] != np.nan:
            min_fpr = fpr[i]
            index_fpr = i
        
        if accuracy[i] > max_accuracy and accuracy[i] != np.nan:
            max_accuracy = accuracy[i]
            index_accuracy = i

        if fnr[i] > min_fnr and fnr[i] != np.nan:
            min_fnr = fnr[i]
            index_fnr = i

        if ppv[i] > max_ppv and ppv[i] != np.nan:
            max_ppv = ppv[i]
            index_ppv = i
        counter += 1

    if counter == 0:
        return
    #f.write("\nField: " + str(y_field) + " SystemId: " + str(systemId) + " Interval: " + str(int(interval.total_seconds())))
    f.write("SystemId: " + str(systemId))
    f.write("\nMax F1-score was for threshold: " + str(thresholds[index_f1]) + " with a F1-score of " + str(f1_scores[index_f1]) + " a TPR of: " + str(
            tpr[index_f1]) + " a FPR of: " + str(fpr[index_f1]) + " an accuracy of: " + str(accuracy[index_f1]) + " a FNR of: " + str(fnr[index_f1]) + 
            " and a PPV of: " + str(ppv[index_f1]))
    
    f.write("\nMax TPR was for threshold: " + str(thresholds[index_tpr]) + " with a F1-score of " + str(f1_scores[index_tpr]) + " a TPR of: " + str(
            tpr[index_tpr]) + " a FPR of: " + str(fpr[index_tpr]) + " an accuracy of: " + str(accuracy[index_tpr]) + " a FNR of: " + str(fnr[index_tpr]) +
            " and a PPV of: " + str(ppv[index_tpr]))
    
    f.write("\nMin FPR was for threshold: " + str(thresholds[index_fpr]) + " with a F1-score of " + str(f1_scores[index_fpr]) + " a TPR of: " + str(
            tpr[index_fpr]) + " a FPR of: " + str(fpr[index_fpr]) + " an accuracy of: " + str(accuracy[index_fpr]) + " a FNR of: " + str(fnr[index_fpr]) + 
            " and a PPV of: " + str(ppv[index_fpr]))
    
    f.write("\nMax accuracy was for threshold: " + str(thresholds[index_accuracy]) + " with a F1-score of " + str(f1_scores[index_accuracy]) + " a TPR of: " + str(
            tpr[index_accuracy]) + " a FPR of: " + str(fpr[index_accuracy]) + " an accuracy of: " + str(accuracy[index_accuracy]) + " a FNR of: " + str(fnr[index_accuracy]) +
            " and a PPV of: " + str(ppv[index_accuracy]))
    
    f.write("\nMin FNR was for threshold: " + str(thresholds[index_fnr]) + " with a F1-score of " + str(f1_scores[index_fnr]) + " a TPR of: " + str(
            tpr[index_fnr]) + " a FPR of: " + str(fpr[index_fnr]) + " an accuracy of: " + str(accuracy[index_fnr]) + " a FNR of: " + str(fnr[index_fnr]) +
            " and a PPV of: " + str(ppv[index_fnr]))
    
    f.write("\nMax PPV was for threshold: " + str(thresholds[index_ppv]) + " with a F1-score of " + str(f1_scores[index_ppv]) + " a TPR of: " + str(
            tpr[index_ppv]) + " a FPR of: " + str(fpr[index_ppv]) + " an accuracy of: " + str(accuracy[index_ppv]) + " a FNR of: " + str(fnr[index_ppv]) +
            " and a PPV of: " + str(ppv[index_ppv]))
    f.write("\n\n")
    f.close()
        
systems = ["teknobyen-gw1", "tromso-gw5",
           "hoytek-gw2", "bergen-gw3", "trd-gw", "ifi2-gw5"]
attackDate="08.03.23"
intervals = [timedelta(minutes = 5), timedelta(minutes = 10), timedelta(minutes = 15)]
for interval in intervals:
    for systemId in systems:
        findGoodThresholdFromFile("SYN", systemId, interval, attackDate)
