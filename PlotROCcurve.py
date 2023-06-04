from pathlib import Path
import matplotlib.pyplot as plt
import json
from datetime import datetime, timedelta
import matplotlib.dates as mdates
import pandas as pd
from sklearn.metrics import auc

'''
    Make a plot based on arrays of values and timestamps
'''
def makeROCcurve(y_field, dataSet, dataType, systemId, intervals, attackDate):
    p = Path('ThresholdDecision') 
    plotPath = Path('Plots')

    if dataType == "Entropy":
        decisionPath = p / 'Entropy'
        plotting = plotPath / 'Entropy'
    elif dataType == "Threshold":
        decisionPath = p / 'Threshold'
        plotting = plotPath / 'Threshold'
    elif dataType == "TopKFlows":
        decisionPath = p / 'TopKFlows'
        plotting = plotPath / 'TopKFlows'
    
    if dataSet == "NetFlow":
        decisionPath = decisionPath / 'NetFlow'
        
    elif dataSet == "Telemetry":
        decisionPath = decisionPath / 'Telemetry'

    if attackDate == "08.03.23":
        fileString = "0803"
        q = decisionPath /'Attack0803'
        plotting = plotting / 'Attack0803'
    elif attackDate == "17.03.23":
        fileString = "1703"
        q = decisionPath /'Attack1703' 
        plotting = plotting / 'Attack1703' 
    elif attackDate == "24.03.23":
        fileString = "2403"
        q = decisionPath /'Attack2403' 
        plotting = plotting / 'Attack2403' 

    if dataSet == "NetFlow":
        plotting = plotting / 'NetFlow'/ 'ROC'
        
    elif dataSet == "Telemetry":
        plotting = plotting / 'Telemetry' / 'ROC'

    if intervals == 0:
        dataFile = str(q) + "/" + str(y_field) +".attack."+str(attackDate)+ "."+str(systemId)+ ".csv"
        if not Path(dataFile).exists():
            return
        data = pd.read_csv(dataFile)
        if len(data) == 0:
            return
        tpr = pd.to_numeric(data["TPR"],errors='coerce')
        fpr = pd.to_numeric(data["FPR"],errors='coerce')

        truePositiveRate = []
        falsePositiveRate = []
        for i in range(len(tpr) -1, -1, -1):
            truePositiveRate.append(tpr[i])
            falsePositiveRate.append(fpr[i])
        auc_value = auc(falsePositiveRate, truePositiveRate)
        fig, axs = plt.subplots(1, 1, figsize=(7, 7))
    
        axs.plot(falsePositiveRate ,truePositiveRate, color="#162931", label="AUC=%.3f"%auc_value)
        axs.set_title("Roc curve", fontsize=20)
        axs.set_xlabel("False Positive Rate", fontsize=20)
        axs.set_ylabel("True Positive Rate", fontsize=20)
        axs.tick_params(axis='both', which='major', labelsize=15)
        fig.tight_layout()
        fig.legend(fontsize=15, loc="right")

        if not plotting.exists():
            plotting.mkdir()
        fig.savefig(str(plotting) + "/"+  str(systemId)+ "." + str(y_field)+ ".png", dpi=500)
        plt.close(fig)
        return
    fig, axs = plt.subplots(1, 1, figsize=(7, 7))
    colors = ["#7F6A93",'#B96B37','#60634E']
    colorCounter = 0
    for interval in intervals:
        dataFile = str(q) + "/" + str(y_field) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv"

        if not Path(dataFile).exists():
            plt.close(fig)
            return
        data = pd.read_csv(dataFile)
        if len(data) == 0:
            plt.close(fig)
            return
        tpr = pd.to_numeric(data["TPR"],errors='coerce')
        fpr = pd.to_numeric(data["FPR"],errors='coerce')

        truePositiveRate = []
        falsePositiveRate = []
        for i in range(len(tpr) -1, -1, -1):
            truePositiveRate.append(tpr[i])
            falsePositiveRate.append(fpr[i])
        auc_value = auc(falsePositiveRate, truePositiveRate)
    
        axs.plot(falsePositiveRate ,truePositiveRate, color=colors[colorCounter], label="Interval: "+ str(int(interval.total_seconds()/60)) +" min\nAUC=%.3f"%auc_value)
        colorCounter += 1
    axs.set_title("Roc curve", fontsize=20)
    axs.set_xlabel("False Positive Rate", fontsize=20)
    axs.set_ylabel("True Positive Rate", fontsize=20)
    axs.tick_params(axis='both', which='major', labelsize=15)
    fig.tight_layout()
    fig.legend(fontsize=15, loc="right")

    if not plotting.exists():
        plotting.mkdir()
    fig.savefig(str(plotting) + "/"+  str(systemId)+ "." + str(y_field)+ ".png", dpi=500)
    
    plt.close(fig)

systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]

attackDates = ["08.03.23", "17.03.23","24.03.23"]
intervals = [timedelta(minutes = 5),timedelta(minutes = 10), timedelta(minutes = 15)]
'''y_fields = ["dstEntropy", "dstEntropyRate","srcEntropy", "srcEntropyRate", "flowEntropy", "flowEntropyRate", "numberOfFlows", "icmpRatio", 
            "icmpPackets", "packetSizeEntropy", "packetSizeEntropyRate", "numberOfPackets", "numberOfBytes", "SYN.dstEntropy", "SYN.srcEntropy", "SYN.flowEntropy"]
print("NetFlow entropy")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        for systemId in systems:
            print(systemId)
            makeROCcurve(y_field, "NetFlow", "Entropy", systemId, intervals, attackDate)
            

y_fields= ["entropy_packet_size","entropy_rate_packet_size","numberOfPackets","numberOfBytes"]
print("Telemetry entropy")
for attackDate in attackDates:
    if attackDate != "24.03.23":
        continue
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        if y_field != "numberOfBytes":
            continue
        print(y_field)
        for systemId in systems:
            print(systemId)
            makeROCcurve(y_field, "Telemetry", "Entropy", systemId, intervals, attackDate)


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
            makeROCcurve(y_field, "NetFlow", "Threshold", systemId, intervals, attackDate)
'''
y_fields = ["SYN"]
print("NetFlow SYN")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        for systemId in systems:
            print(systemId)
            makeROCcurve(y_field, "NetFlow", "Threshold", systemId, 0, attackDate)


y_fields= ["egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets", "ingress_stats__if_1sec_pkts", "ingress_stats__if_1sec_octets", "MaxVar.egress_queue_info__0__cur_buffer_occupancy", "MaxVar.egress_stats__if_1sec_pkts", "MaxVar.egress_stats__if_1sec_octets", "MaxVar.ingress_stats__if_1sec_pkts", "MaxVar.ingress_stats__if_1sec_octets"]
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        for systemId in systems:
            print(systemId)
            makeROCcurve(y_field, "Telemetry", "Threshold", systemId, 0, attackDate)
            
y_fields = ["TopKFlows"]
print("NetFlow TopKFlows")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        for systemId in systems:
            print(systemId)
            makeROCcurve(y_field, "NetFlow", "TopKFlows", systemId, 0, attackDate)