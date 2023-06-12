

from datetime import datetime, timedelta
from pathlib import Path
import numpy as np
import pandas as pd


def findGoodThresholdFromFile(y_field, dataSet, dataType, systems, interval, attackDate):
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
        if not q.exists():
            q.mkdir(parents=True)
        f = open(str(q) + "/MinMax/MaxTPR."+ str(y_field) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".csv", "a")
        f.write("SystemId,threshold,maxTPR")
    else:
        if not q.exists():
            q.mkdir(parents=True)
        f = open(str(q) + "/MinMax/MaxTPR."+ str(y_field) +".attack."+str(attackDate)+ ".csv", "a")
        f.write("SystemId,threshold,maxTPR")

    for systemId in systems:
        if interval != 0:
            dataFile = str(q) + "/" + str(y_field) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv"
            if not Path(dataFile).exists():
                continue
        else:
            dataFile = str(q) + "/" + str(y_field) +".attack."+str(attackDate)+ "."+str(systemId)+ ".csv"
            if not Path(dataFile).exists():
                continue

        data = pd.read_csv(dataFile)
        thresholds = pd.to_numeric(data["Threshold"],errors='coerce')
        tpr = pd.to_numeric(data["TPR"],errors='coerce')
        tp = pd.to_numeric(data["TP"], errors='coerce')

        max_tpr = 0
        index_tpr = 0
        counter = 0

        for i in range(len(thresholds)):
            if tp[i] == 0:
                continue

            if tpr[i] >= max_tpr and tpr[i] != np.nan:
                max_tpr = tpr[i]
                index_tpr = i

            counter += 1

        if counter == 0:
            continue
        f.write("\n" + str(systemId) + "," + str(thresholds[index_tpr]) + "," + str(tpr[index_tpr]))
        
    f.close()
        
systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
attackDates = ["08.03.23", "17.03.23","24.03.23"]
y_fields = ["dstEntropy", "dstEntropyRate","srcEntropy", "srcEntropyRate", "flowEntropy", "flowEntropyRate", "numberOfFlows", "icmpRatio", 
            "icmpPackets", "packetSizeEntropy", "packetSizeEntropyRate", "numberOfPackets", "numberOfBytes", "SYN.dstEntropy", "SYN.srcEntropy", "SYN.flowEntropy"]
intervals = [timedelta(minutes = 5),timedelta(minutes = 10), timedelta(minutes = 15)]
print("NetFlow entropy")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        for interval in intervals:
            print(interval)
            findGoodThresholdFromFile(y_field, "NetFlow", "Entropy", systems, interval, attackDate)

y_fields= ["entropy_packet_size_ingress","entropy_rate_packet_size_ingress","numberOfPackets_ingress","numberOfBytes_ingress",
           "entropy_packet_size_egress","entropy_rate_packet_size_egress","numberOfPackets_egress","numberOfBytes_egress"]
print("Telemetry entropy")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        for interval in intervals:
            print(interval)
            findGoodThresholdFromFile(y_field, "Telemetry", "Entropy", systems, interval, attackDate)


y_fields = ["ICMPDstUnreachable"]
intervals = [timedelta(minutes = 5),timedelta(minutes = 10), timedelta(minutes = 15)]
print("NetFlow ICMP dst unreachable")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        for interval in intervals:
            print(interval)
            findGoodThresholdFromFile(y_field, "NetFlow", "Threshold", systems, interval, attackDate)

y_fields = ["SYN"]
print("NetFlow SYN")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        findGoodThresholdFromFile(y_field, "NetFlow", "Threshold", systems, 0, attackDate)

y_fields = ["TopKFlows"]
print("NetFlow TopKFlows")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        findGoodThresholdFromFile(y_field, "NetFlow", "TopKFlows", systems, 0, attackDate)

y_fields= ["egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets", "ingress_stats__if_1sec_pkts", "ingress_stats__if_1sec_octets", "MaxVar.egress_queue_info__0__cur_buffer_occupancy", "MaxVar.egress_stats__if_1sec_pkts", "MaxVar.egress_stats__if_1sec_octets", "MaxVar.ingress_stats__if_1sec_pkts", "MaxVar.ingress_stats__if_1sec_octets"]
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        findGoodThresholdFromFile(y_field, "Telemetry", "Threshold", systems, 0, attackDate)