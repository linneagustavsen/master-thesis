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
        fig.savefig(str(plotting) + "/"+  str(systemId)+ "." + str(y_field)+ ".pdf", dpi=300)
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
        plotting.mkdir(parents=True)
    fig.savefig(str(plotting) + "/"+  str(systemId)+ "." + str(y_field)+ ".pdf", dpi=300)
    
    plt.close(fig)

def makeROCcurveSystemsTogether(y_field, dataSet, dataType, intervals,systems, attackDate):
    if dataSet == "Telemetry":
        systems = ["trd-gw", "ifi2-gw5", "bergen-gw3", "tromso-gw5", "teknobyen-gw1", "teknobyen-gw2", "oslo-gw1", "hoytek-gw2", "hovedbygget-gw", "narvik-gw3", "narvik-gw4", "ma2-gw",  "tromso-fh-gw", "narvik-kv-gw", "stangnes-gw", "rodbergvn-gw2"]
        
        anonymizedSystems = ["AR1", "AR2", "AR3", "AR4", "VR", "CR1", "CR2", "CR3", "CR4", "CR5", "CR6", "CR7", "CR8", "CR9", "CR10", "CR11"]
    else:
        systems = ["trd-gw", "ifi2-gw5", "bergen-gw3", "tromso-gw5", "teknobyen-gw1",  "hoytek-gw2"]
        
        anonymizedSystems = ["AR1", "AR2", "AR3", "AR4", "VR", "CR3"]
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
        total_auc_roc = 0
        total_auc_pr = 0
        fig, axs = plt.subplots(1, 1, figsize=(7, 7))
        fig1, axs1 = plt.subplots(1, 1, figsize=(7, 7))
        colors = ['#997B66', '#D08C60', '#DAA684', '#9B9B7A', '#797D62', '#7F6A93',
          '#5C8FBB', '#FFAF42', '#A0D37D', '#CE6E95', '#4E5B7E', '#FF8C66',
          '#47A8A6', '#D0653F', '#D8C26B', '#A4848A']
        colorCounter = 0
        for systemId in systems:
            print(systemId)
            dataFile = str(q) + "/" + str(y_field) +".attack."+str(attackDate)+ "."+str(systemId)+ ".csv"
            if not Path(dataFile).exists():
                print("file doesnt exist", dataFile)
                colorCounter += 1
                continue
            data = pd.read_csv(dataFile)
            if len(data) == 0:
                print("data is empty")
                colorCounter += 1
                continue
            tpr = pd.to_numeric(data["TPR"],errors='coerce').dropna()
            fpr = pd.to_numeric(data["FPR"],errors='coerce').dropna()
            if len(tpr) == 0 or len(fpr) == 0:
                colorCounter += 1
                continue

            truePositiveRate = []
            falsePositiveRate = []
            for i in range(len(tpr) -1, -1, -1):
                truePositiveRate.append(tpr[i])
                falsePositiveRate.append(fpr[i])
            auc_value = auc(falsePositiveRate, truePositiveRate)

            axs1.plot(falsePositiveRate ,truePositiveRate, color=colors[colorCounter], label="Router: "+anonymizedSystems[colorCounter] +"\nAUC=%.3f"%auc_value)

            recall = pd.to_numeric(data["TPR"],errors='coerce').dropna()
            precision = pd.to_numeric(data["PPV"],errors='coerce').dropna()

            if len(recall) == 0 or len(precision) == 0:
                colorCounter += 1
                continue

            truePositiveRate = []
            ppv = []
            smallestLength = 0
            if len(recall) < len(precision):
                smallestLength = len(recall)
            else:
                smallestLength = len(precision)
            for i in range(smallestLength -1, -1, -1):
                truePositiveRate.append(recall[i])
                ppv.append(precision[i])
            auc_value = auc(truePositiveRate, ppv)
        
            axs.plot(truePositiveRate ,ppv, color=colors[colorCounter], label="Router:" + anonymizedSystems[colorCounter]+"\nAUC=%.3f"%auc_value)

            colorCounter += 1
    else:
        fig, axs = plt.subplots(1, 1, figsize=(10, 10))
        fig1, axs1 = plt.subplots(1, 1, figsize=(10, 10))
        colors = ['#997B66', '#D08C60', '#DAA684', '#9B9B7A', '#797D62', '#7F6A93',
          '#5C8FBB', '#FFAF42', '#A0D37D', '#CE6E95', '#4E5B7E', '#FF8C66',
          '#47A8A6', '#D0653F', '#D8C26B', '#A4848A', '#5D934E', '#CA4B54', '#997B66', '#D08C60', '#DAA684', '#9B9B7A', '#797D62', '#7F6A93',
        '#5C8FBB', '#FFAF42', '#A0D37D', '#CE6E95', '#4E5B7E', '#FF8C66',
        '#47A8A6', '#D0653F', '#D8C26B', '#A4848A', '#5D934E', '#CA4B54', '#997B66', '#D08C60', '#DAA684', '#9B9B7A', '#797D62', '#7F6A93',
        '#5C8FBB', '#FFAF42', '#A0D37D', '#CE6E95', '#4E5B7E', '#FF8C66',
        '#47A8A6', '#D0653F', '#D8C26B', '#A4848A', '#5D934E', '#CA4B54']
        colorCounter = 0
        systemCounter = 0
        total_auc_roc = 0
        total_auc_pr = 0
        for systemId in systems:
            for interval in intervals:
                dataFile = str(q) + "/" + str(y_field) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv"
                if not Path(dataFile).exists():
                    print("file doesnt exist", dataFile)
                    colorCounter += 1
                    continue
                data = pd.read_csv(dataFile)
                if len(data) == 0:
                    print("data is empty")
                    colorCounter += 1
                    continue
                tpr = pd.to_numeric(data["TPR"],errors='coerce').dropna()
                fpr = pd.to_numeric(data["FPR"],errors='coerce').dropna()
                if len(tpr) == 0 or len(fpr) == 0:
                    colorCounter += 1
                    continue

                truePositiveRate = []
                falsePositiveRate = []
                for i in range(len(tpr) -1, -1, -1):
                    truePositiveRate.append(tpr[i])
                    falsePositiveRate.append(fpr[i])
                auc_value = auc(falsePositiveRate, truePositiveRate)
                total_auc_roc += auc_value
                axs1.plot(falsePositiveRate ,truePositiveRate, color=colors[colorCounter], label="Router: "+anonymizedSystems[systemCounter] +", Interval: "+ str(int(interval.total_seconds()/60)) +" min, AUC=%.3f"%auc_value)

                recall = pd.to_numeric(data["TPR"],errors='coerce').dropna()
                precision = pd.to_numeric(data["PPV"],errors='coerce').dropna()
                #print(recall, precision)

                if len(recall) == 0 or len(precision) == 0:
                    colorCounter += 1
                    continue

                truePositiveRate = []
                ppv = []
                smallestLength = 0
                if len(recall) < len(precision):
                    smallestLength = len(recall)
                else:
                    smallestLength = len(precision)
                for i in range(smallestLength -1, -1, -1):
                    truePositiveRate.append(recall[i])
                    ppv.append(precision[i])
                auc_value = auc(truePositiveRate, ppv)
                total_auc_pr += auc_value
                axs.plot(truePositiveRate ,ppv, color=colors[colorCounter], label="Router: "+anonymizedSystems[systemCounter] +", Interval: "+ str(int(interval.total_seconds()/60)) +" min, AUC=%.3f"%auc_value)

                colorCounter += 1
            systemCounter += 1

    print(total_auc_roc/colorCounter)
    print(total_auc_pr/colorCounter)
    axs.set_title("Precision-Recall curve", fontsize=20)
    axs.set_xlabel("Recall", fontsize=20)
    axs.set_ylabel("Precision", fontsize=20)
    axs.tick_params(axis='both', which='major', labelsize=15)
    #fig.tight_layout()
    fig.legend(fontsize=15, loc="right")

    if not plotting.exists():
        plotting.mkdir()
    fig.savefig(str(plotting) + "/AllSystemsPR." + str(y_field)+ ".pdf", dpi=300)

    axs1.set_title("ROC curve", fontsize=20)
    axs1.set_xlabel("FPR", fontsize=20)
    axs1.set_ylabel("TPR", fontsize=20)
    axs1.tick_params(axis='both', which='major', labelsize=15)
    #fig.tight_layout()
    fig1.legend(fontsize=15, loc="right")

    if not plotting.exists():
        plotting.mkdir()
    fig1.savefig(str(plotting) + "/AllSystemsROC." + str(y_field)+ ".pdf", dpi=300)
    plt.close(fig)


def makeROCcurveTogether(y_field_netflow, y_field_telemetry, dataType, systems, intervals, attackDate):
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

    if attackDate == "08.03.23":
        fileString = "0803"
        qNetFlow = decisionPath / 'NetFlow' /'Attack0803' 
        qTelemetry = decisionPath / 'Telemetry' /'Attack0803' 
        plotting = plotting / 'Attack0803'
    elif attackDate == "17.03.23":
        fileString = "1703"
        qNetFlow = decisionPath / 'NetFlow' /'Attack1703' 
        qTelemetry = decisionPath / 'Telemetry' /'Attack1703'
        plotting = plotting / 'Attack1703' 
    elif attackDate == "24.03.23":
        fileString = "2403"
        qNetFlow = decisionPath / 'NetFlow' /'Attack2403' 
        qTelemetry = decisionPath / 'Telemetry' /'Attack2403'
        plotting = plotting / 'Attack2403' 

    fig, axs = plt.subplots(1, 1, figsize=(10, 10))
    colors = ['#997B66', '#D08C60', '#DAA684', '#9B9B7A', '#797D62', '#7F6A93',
        '#5C8FBB', '#FFAF42', '#A0D37D', '#CE6E95', '#4E5B7E', '#FF8C66',
        '#47A8A6', '#D0653F', '#D8C26B', '#A4848A', '#5D934E', '#CA4B54', ]
    colorCounter = 0
    systemCounter = 0
    total_auc_roc = 0
    total_auc_pr = 0
    for systemId in systems:
        for interval in intervals:
            dataFile_netflow= str(qNetFlow) + "/" + str(y_field_netflow) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv"
            dataFile_telemetry = str(qTelemetry) + "/" + str(y_field_telemetry) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv"

            if not Path(dataFile_netflow).exists():
                plt.close(fig)
                print("NetFlow file doesnt exist", str(qNetFlow) + "/" + str(y_field_netflow) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
                continue
            if not Path(dataFile_telemetry).exists():
                print("Telemetry file doesnt exist")
                plt.close(fig)
                continue
            data_netflow = pd.read_csv(dataFile_netflow)
            data_telemetry = pd.read_csv(dataFile_telemetry)
            if len(data_netflow) == 0:
                plt.close(fig)
                return
            if len(data_telemetry) == 0:
                plt.close(fig)
                return
            tpr = pd.to_numeric(data_netflow["TPR"],errors='coerce')
            fpr = pd.to_numeric(data_netflow["FPR"],errors='coerce')

            truePositiveRate = []
            falsePositiveRate = []
            for i in range(len(tpr) -1, -1, -1):
                truePositiveRate.append(tpr[i])
                falsePositiveRate.append(fpr[i])
            auc_value = auc(falsePositiveRate, truePositiveRate)
        
            axs.plot(falsePositiveRate ,truePositiveRate, color=colors[colorCounter],label="Interval: "+ str(int(interval.total_seconds()/60)) +" min\nAUC=%.3f"%auc_value)


            tpr = pd.to_numeric(data_telemetry["TPR"],errors='coerce')
            fpr = pd.to_numeric(data_telemetry["FPR"],errors='coerce')

            truePositiveRate = []
            falsePositiveRate = []
            for i in range(len(tpr) -1, -1, -1):
                truePositiveRate.append(tpr[i])
                falsePositiveRate.append(fpr[i])
            auc_value = auc(falsePositiveRate, truePositiveRate)
        
            axs.plot(falsePositiveRate ,truePositiveRate, color=colors[colorCounter],  linestyle='dashed', label="Interval: "+ str(int(interval.total_seconds()/60)) +" min\nAUC=%.3f"%auc_value)


            colorCounter += 1
    axs.set_title("Roc curve", fontsize=20)
    axs.set_xlabel("False Positive Rate", fontsize=20)
    axs.set_ylabel("True Positive Rate", fontsize=20)
    axs.tick_params(axis='both', which='major', labelsize=15)
    fig.tight_layout()
    fig.legend(fontsize=7, loc="right")

    if not plotting.exists():
        plotting.mkdir(parents=True)
    print(str(plotting) + "/ROC." + str(y_field_netflow)+ ".pdf")
    fig.savefig(str(plotting) + "/ROC." + str(y_field_netflow)+ ".pdf", dpi=300)
    
    plt.close(fig)

systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]

attackDates = ["24.03.23"]
intervals = [timedelta(minutes = 5),timedelta(minutes = 10), timedelta(minutes = 15)]
y_fields = ["dstEntropy", "dstEntropyRate","srcEntropy", "srcEntropyRate", "flowEntropy", "flowEntropyRate", "numberOfFlows", "icmpRatio", 
            "icmpPackets", "packetSizeEntropy", "packetSizeEntropyRate", "numberOfPackets", "numberOfBytes", "SYN.dstEntropy", "SYN.srcEntropy", "SYN.flowEntropy"]
y_fields_netflow = ["numberOfPackets", "numberOfBytes"]
y_fields_telemetry= ["numberOfPackets_ingress","numberOfBytes_ingress"]
'''  print("NetFlow entropy")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for i in range(len(y_fields_netflow)):
        makeROCcurveTogether(y_fields_netflow[i], y_fields_telemetry[i], "Entropy", systems, intervals, attackDate)
        for systemId in systems:
            print(systemId)
            makeROCcurve(y_field, "NetFlow", "Entropy", systemId, intervals, attackDate)
          

y_fields= ["entropy_packet_size_ingress","entropy_rate_packet_size_ingress","numberOfPackets_ingress","numberOfBytes_ingress", 
           "entropy_packet_size_egress","entropy_rate_packet_size_egress","numberOfPackets_egress","numberOfBytes_egress"]
print("Telemetry entropy")
for attackDate in attackDates:
    if attackDate != "24.03.23":
        continue
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        makeROCcurveSystemsTogether(y_field, "Telemetry", "Entropy", intervals,systems, attackDate)

'''

y_fields = ["ICMPDstUnreachable"]
intervals = [timedelta(minutes = 5),timedelta(minutes = 10), timedelta(minutes = 15)]
print("NetFlow ICMP dst unreachable")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        makeROCcurveSystemsTogether(y_field, "NetFlow", "Threshold", intervals, systems, attackDate)
'''
y_fields = ["SYN"]
print("NetFlow SYN")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        makeROCcurveSystemsTogether(y_field, "NetFlow", "Threshold", systems, attackDate)
        for systemId in systems:
            print(systemId)
            #makeROCcurve(y_field, "NetFlow", "Threshold", systemId, 0, attackDate)
            

systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
y_fields= ["egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets", "ingress_stats__if_1sec_pkts", "ingress_stats__if_1sec_octets", "MaxVar.egress_queue_info__0__cur_buffer_occupancy", "MaxVar.egress_stats__if_1sec_pkts", "MaxVar.egress_stats__if_1sec_octets", "MaxVar.ingress_stats__if_1sec_pkts", "MaxVar.ingress_stats__if_1sec_octets"]
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        makeROCcurveSystemsTogether(y_field, "Telemetry", "Threshold", 0, systems, attackDate)
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
        makeROCcurveSystemsTogether(y_field, "NetFlow", "TopKFlows", 0, systems, attackDate)

y_fields_telemetry= ["entropy_packet_size_ingress","entropy_rate_packet_size_ingress","numberOfPackets_ingress","numberOfBytes_ingress"]
y_fields_netflow = ["packetSizeEntropy", "packetSizeEntropyRate", "numberOfPackets", "numberOfBytes"]
print("Telemetry entropy")
for attackDate in attackDates:
    if attackDate != "24.03.23":
        continue
    print("\n")
    print(attackDate)
    for i in range(len(y_fields_netflow)):
        for systemId in systems:
            print(systemId)
            makeROCcurveTogether(y_fields_netflow[i], y_fields_telemetry[i], "Entropy", systemId, intervals, attackDate)'''  
