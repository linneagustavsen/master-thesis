from pathlib import Path
from matplotlib.colors import LinearSegmentedColormap
import matplotlib.pyplot as plt
import json
from datetime import datetime, timedelta
import matplotlib.dates as mdates
import pandas as pd
from sklearn.metrics import auc
import seaborn as sns

'''
    Make a plot based on arrays of values and timestamps
'''
def makePrecisionRecallCurve(y_field, dataSet, dataType, systems, intervals, attackDate):
    anonymizedSystems = ["AR1", "AR2", "AR3", "AR4", "VR", "CR1", "CR2", "CR3", "CR4", "CR5", "CR6", "CR7", "CR8", "CR9", "CR10", "CR11"]
    
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
        plotting = plotting / 'NetFlow'/ 'PR'
        
    elif dataSet == "Telemetry":
        plotting = plotting / 'Telemetry' / 'PR'

    if intervals == 0:
        fig, axs = plt.subplots(1, 1, figsize=(10, 10))
        colors = [
            '#b2182b',  # red
            '#d6604d',  # light red
            '#f4a582',  # salmon
            '#60634E',  # light blue
            '#92c5de',  # blue
            '#4393c3',  # dark blue
            '#2166ac',  # deep blue
            '#B96B37',  # light green
            '#7fbc41',  # green
            '#238b45',  # dark green
            '#006d2c',  # deep green
            '#addd8e',  # light lime green
            '#78c679',  # lime green
            '#7F6A93',  # yellow
            '#fee08b',  # pale yellow
            '#fdae61'   # orange
        ]
        colorCounter = 0
        for systemId in systems:
            dataFile = str(q) + "/" + str(y_field) +".attack."+str(attackDate)+ "."+str(systemId)+ ".csv"
            if not Path(dataFile).exists():
                return
            data = pd.read_csv(dataFile)
            if len(data) == 0:
                return
            recall = pd.to_numeric(data["TPR"],errors='coerce')
            precision = pd.to_numeric(data["PPV"],errors='coerce')

            truePositiveRate = []
            ppv = []
            for i in range(len(recall) -1, -1, -1):
                truePositiveRate.append(recall[i])
                ppv.append(precision[i])
            auc_value = auc(truePositiveRate, ppv)
        
            axs.plot(truePositiveRate ,ppv, color=colors[colorCounter], label="Router:" + anonymizedSystems[colorCounter]+"\nAUC=%.3f"%auc_value)
            colorCounter += 1
        axs.set_title("PR curve", fontsize=20)
        axs.set_xlabel("Recall", fontsize=20)
        axs.set_ylabel("Precision", fontsize=20)
        axs.tick_params(axis='both', which='major', labelsize=15)
        fig.tight_layout()
        fig.legend(fontsize=15, loc="right")

        if not plotting.exists():
            plotting.mkdir()
        fig.savefig(str(plotting) + "/" + str(y_field)+ ".pdf", dpi=300)
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
        recall = pd.to_numeric(data["TPR"],errors='coerce')
        precision = pd.to_numeric(data["PPV"],errors='coerce')

        truePositiveRate = []
        ppv = []
        for i in range(len(recall) -1, -1, -1):
            truePositiveRate.append(recall[i])
            ppv.append(precision[i])
        auc_value = auc(truePositiveRate, ppv)
        fig, axs = plt.subplots(1, 1, figsize=(7, 7))
    
        axs.plot(truePositiveRate ,ppv, color=colors[colorCounter], label="Interval: "+ str(int(interval.total_seconds()/60)) +" min\nAUC=%.3f"%auc_value)
        colorCounter += 1
    axs.set_title("PR curve", fontsize=20)
    axs.set_xlabel("False Positive Rate", fontsize=20)
    axs.set_ylabel("True Positive Rate", fontsize=20)
    axs.tick_params(axis='both', which='major', labelsize=15)
    fig.tight_layout()
    fig.legend(fontsize=15, loc="right")

    if not plotting.exists():
        plotting.mkdir(parents=True)
    fig.savefig(str(plotting) + "/"+  str(systemId)+ "." + str(y_field)+ ".pdf", dpi=300)
    
    plt.close(fig)

def makePrecisionRecallHeatMap(y_fields, dataSet, dataType, systems, intervals, attackDate):
    anonymizedSystems = ["AR1", "AR2", "AR3", "AR4", "VR", "CR1", "CR2", "CR3", "CR4", "CR5", "CR6", "CR7", "CR8", "CR9", "CR10", "CR11"]
    
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
        plotting = plotting / 'NetFlow'/ 'PR'
        
    elif dataSet == "Telemetry":
        plotting = plotting / 'Telemetry' / 'PR'

    fig, axs = plt.subplots(1, 1, figsize=(10, 10))
    colorCounter = 0
    data_roc = []
    data_pr = []
    
    for systemId in systems:
        row_roc = []
        row_pr = []
        for interval in intervals:
            dataFile = str(q) + "/" + str(y_field) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv"

            if not Path(dataFile).exists():
                return
            data = pd.read_csv(dataFile)
            if len(data) == 0:
                return
            tpr = pd.to_numeric(data["TPR"],errors='coerce')
            precision = pd.to_numeric(data["PPV"],errors='coerce')
            fpr = pd.to_numeric(data["FPR"],errors='coerce')

            truePositiveRate = []
            falsePositiveRate = []
            ppv= []
            for i in range(len(tpr) -1, -1, -1):
                truePositiveRate.append(tpr[i])
                falsePositiveRate.append(fpr[i])
                ppv.append(precision[i])
            auc_value_roc = auc(falsePositiveRate, truePositiveRate)
            auc_value_pr = auc(truePositiveRate, ppv)
        
        
            row_roc.append(auc_value_roc)
            row_pr.append(auc_value_pr)
        data_roc.append(row_roc)
        data_pr.append(row_pr)

    x_labels = []

    colorsGood = ["#E9D4C7","#CB997E", "#3A2D32"]
    cmapGood = LinearSegmentedColormap.from_list("custom_cmap", colorsGood)
    fig, ax = plt.subplots(figsize=(100, 100))
    sns.heatmap(data_roc, annot=True, fmt=".3f", cmap=cmapGood, ax=ax, center=0.5, vmax=1, xticklabels=x_labels, yticklabels=anonymizedSystems)


    axs.set_title("PR curve", fontsize=20)
    axs.set_xlabel("Recall", fontsize=20)
    axs.set_ylabel("Precision", fontsize=20)
    axs.tick_params(axis='both', which='major', labelsize=15)
    fig.tight_layout()
    fig.legend(fontsize=15, loc="right")

    if not plotting.exists():
        plotting.mkdir()
    fig.savefig(str(plotting) + "/" + str(y_field)+ ".pdf", dpi=300)
    plt.close(fig)
    

systems = ["trd-gw", "ifi2-gw5", "bergen-gw3", "tromso-gw5", "teknobyen-gw1", "teknobyen-gw2", "oslo-gw1", "hoytek-gw2", "hovedbygget-gw", "narvik-gw3", "narvik-gw4", "ma2-gw",  "tromso-fh-gw", "narvik-kv-gw", "stangnes-gw", "rodbergvn-gw2"]

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
            makePrecisionRecallCurve(y_field, "NetFlow", "Entropy", systemId, intervals, attackDate)
            

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
            makePrecisionRecallCurve(y_field, "Telemetry", "Entropy", systemId, intervals, attackDate)


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
            makePrecisionRecallCurve(y_field, "NetFlow", "Threshold", systemId, intervals, attackDate)

y_fields = ["SYN"]
print("NetFlow SYN")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        for systemId in systems:
            print(systemId)
            makePrecisionRecallCurve(y_field, "NetFlow", "Threshold", systemId, 0, attackDate)

'''
attackDates = ["24.03.23"]
y_fields= ["egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets", "ingress_stats__if_1sec_pkts", "ingress_stats__if_1sec_octets", "MaxVar.egress_queue_info__0__cur_buffer_occupancy", "MaxVar.egress_stats__if_1sec_pkts", "MaxVar.egress_stats__if_1sec_octets", "MaxVar.ingress_stats__if_1sec_pkts", "MaxVar.ingress_stats__if_1sec_octets"]
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        makePrecisionRecallCurve(y_field, "Telemetry", "Threshold", systems, 0, attackDate)
'''  
y_fields = ["TopKFlows"]
print("NetFlow TopKFlows")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        for systemId in systems:
            print(systemId)
            makePrecisionRecallCurve(y_field, "NetFlow", "TopKFlows", systemId, 0, attackDate)'''   