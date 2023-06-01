

from datetime import datetime, timedelta
from pathlib import Path
import numpy as np
import pandas as pd


def findGoodThresholdFromFile(y_field, dataSet, dataType, systemId, interval, attackDate):
    p = Path('ThresholdDecision')
    
    if dataType == "Entropy":
        decisionPath = p / 'Entropy'
    elif dataType == "Threshold":
        decisionPath = p / 'Threshold'
    elif dataType == "TopKFlows":
        decisionPath = p / 'TopKFlows'
    
    if dataSet == "NetFlow":
        decisionPath = decisionPath / 'NetFlow'
    elif dataSet == "Telemetry":
        decisionPath = decisionPath / 'Telemetry'

    if attackDate == "08.03.23":
        fileString = "0803"
        q = decisionPath /'Attack0803'
    elif attackDate == "17.03.23":
        fileString = "1703"
        q = decisionPath /'Attack1703' 
    elif attackDate == "24.03.23":
        fileString = "2403"
        q = decisionPath /'Attack2403' 
    
    if interval != 0:
        dataFile = str(q) + "/" + str(y_field) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv"
    else:
        dataFile = str(q) + "/" + str(y_field) +".attack."+str(attackDate)+ "."+str(systemId)+ ".csv"
    if not Path(dataFile).exists():
        return
    
    if not q.exists():
        q.mkdir(parents=True)
    f = open(str(q) + "/MinMax/Max_min_thresholds_"+ y_field + ".txt", "a")

    data = pd.read_csv(dataFile)
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
        if f1_scores[i] >= max_f1 and f1_scores[i] != np.nan:
            max_f1 = f1_scores[i]
            index_f1 = i

        if tpr[i] >= max_tpr and tpr[i] != np.nan:
            max_tpr = tpr[i]
            index_tpr = i

        if fpr[i] <= min_fpr and fpr[i] != np.nan:
            min_fpr = fpr[i]
            index_fpr = i
        
        if accuracy[i] >= max_accuracy and accuracy[i] != np.nan:
            max_accuracy = accuracy[i]
            index_accuracy = i

        if fnr[i] <= min_fnr and fnr[i] != np.nan:
            min_fnr = fnr[i]
            index_fnr = i

        if ppv[i] >= max_ppv and ppv[i] != np.nan:
            max_ppv = ppv[i]
            index_ppv = i
        counter += 1

    if counter == 0:
        return
    if interval != 0:
        f.write("\nField: " + str(y_field) + " SystemId: " + str(systemId) + " Interval: " + str(int(interval.total_seconds())))
    else:
        f.write("\nField: " + str(y_field) + " SystemId: " + str(systemId))
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
    f.write("\n")
    f.close()
        
systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
attackDates = ["08.03.23", "17.03.23","24.03.23"]
attackDates = ["08.03.23"]
y_fields = ["dstEntropy", "dstEntropyRate","srcEntropy", "srcEntropyRate", "flowEntropy", "flowEntropyRate", "numberOfFlows", "icmpRatio", 
            "icmpPackets", "packetSizeEntropy", "packetSizeEntropyRate", "numberOfPackets", "numberOfBytes", "SYN.dstEntropy", "SYN.srcEntropy", "SYN.flowEntropy"]
intervals = [timedelta(minutes = 5),timedelta(minutes = 10), timedelta(minutes = 15)]
print("NetFlow entropy")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        for systemId in systems:
            print(systemId)
            for interval in intervals:
                print(interval)
                findGoodThresholdFromFile(y_field, "NetFlow", "Entropy", systemId, interval, attackDate)

'''y_fields= ["entropy_packet_size","entropy_rate_packet_size","numberOfPackets","numberOfBytes"]
print("Telemetry entropy")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        for systemId in systems:
            print(systemId)
            for interval in intervals:
                print(interval)
                findGoodThresholdFromFile(y_field, "Telemetry", "Entropy", systemId, interval, attackDate)


y_fields = ["ICMPDstUnreachable"]
intervals = [timedelta(minutes = 5),timedelta(minutes = 10), timedelta(minutes = 15)]
print("NetFlow ICMP dst unreachable")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        for systemId in systems:
            print(systemId)
            for interval in intervals:
                print(interval)
                findGoodThresholdFromFile(y_field, "NetFlow", "Threshold", systemId, interval, attackDate)

y_fields = ["SYN"]
print("NetFlow SYN")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        for systemId in systems:
            print(systemId)
            findGoodThresholdFromFile(y_field, "NetFlow", "Threshold", systemId, 0, attackDate)


y_fields= ["egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets", "ingress_stats__if_1sec_pkts", "ingress_stats__if_1sec_octets", "MaxVar.egress_queue_info__0__cur_buffer_occupancy", "MaxVar.egress_stats__if_1sec_pkts", "MaxVar.egress_stats__if_1sec_octets", "MaxVar.ingress_stats__if_1sec_pkts", "MaxVar.ingress_stats__if_1sec_octets"]
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        for systemId in systems:
            print(systemId)
            if (systemId=="hoytek-gw2" or systemId == "narvik-gw4") and y_field == "egress_queue_info__0__cur_buffer_occupancy":
                continue
            findGoodThresholdFromFile(y_field, "Telemetry", "Threshold", systemId, 0, attackDate)

y_fields = ["TopKFlows"]
print("NetFlow TopKFlows")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        for systemId in systems:
            print(systemId)
            findGoodThresholdFromFile(y_field, "NetFlow", "TopKFlows", systemId, 0, attackDate)'''