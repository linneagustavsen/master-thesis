from operator import itemgetter
from pathlib import Path
from pprint import pprint
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
def makeROCcurve(y_field, dataSet, dataType, systemId, attackDate):
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

    def get_cmap(n, name='hsv'):
        '''Returns a function that maps each index in 0, 1, ..., n-1 to a distinct 
        RGB color; the keyword argument name must be a standard mpl colormap name.'''
        return plt.cm.get_cmap(name, n)
    #fig, axs = plt.subplots(1, 1, figsize=(10, 10))
    #cmap = get_cmap(5600)
    frequencies = [timedelta(seconds=5),timedelta(seconds=10), timedelta(seconds=20), timedelta(seconds=30), timedelta(seconds=40), timedelta(seconds=50),timedelta(minutes=1)]
    auc_scores = {}
    auc_scores_pr = {}
    for frequency in frequencies:
        for i in range(1,21):
            interval = timedelta(minutes=i)
            for alpha in range(2, 16):
                if (y_field == "numberOfPackets" or y_field == "numberOfBytes" or y_field == "numberOfFlows" or y_field == "icmpRatio" or y_field == "icmpPackets") and alpha > 2:
                    continue
                for windowSize in range(2,21):
                    dataFile = str(q) + "/RocScoresOnlyFPRandTPR/" + str(y_field) +".alpha."+ str(alpha)+ ".windowSize."+ str(windowSize)+ "."+ str(int(frequency.total_seconds()))+ "secFrequency." +str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv"

                    if not Path(dataFile).exists():
                        print("no file", dataFile)
                        break
                    data = pd.read_csv(dataFile)
                    if len(data) == 0:
                        print("the file is empty")
                        break
                    truePositiveRate = pd.to_numeric(data["TPR"],errors='coerce')
                    falsePositiveRate = pd.to_numeric(data["FPR"],errors='coerce')

                    auc_value = auc(falsePositiveRate, truePositiveRate)

                    if y_field == "numberOfPackets" or y_field == "numberOfBytes" or y_field == "numberOfFlows" or y_field == "icmpRatio" or y_field == "icmpPackets":
                        auc_scores[str("Frequency: " + str(int(frequency.total_seconds())) +"sec Interval: "+ str(int(interval.total_seconds()/60))+ " Window size: "+ str(windowSize) +" min")] = auc_value
                    else:
                        auc_scores[str("Frequency: " + str(int(frequency.total_seconds())) +"sec Interval: "+ str(int(interval.total_seconds()/60))+ " Window size: "+ str(windowSize) +" min α: "+ str(alpha))] = auc_value
                    
                    dataFile = str(q) + "/PrecisionRecall/" + str(y_field) +".alpha."+ str(alpha)+ ".windowSize."+ str(windowSize)+ "."+ str(int(frequency.total_seconds()))+ "secFrequency." +str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv"

                    if not Path(dataFile).exists():
                        print("no file", dataFile)
                        break
                    data = pd.read_csv(dataFile)

                    if len(data) == 0:
                        print("the file is empty")
                        break
                    precision = pd.to_numeric(data["Precision"],errors='coerce')
                    recall = pd.to_numeric(data["Recall"],errors='coerce')
          
                    auc_value = auc(recall, precision)
                    if y_field == "numberOfPackets" or y_field == "numberOfBytes":
                        auc_scores_pr[str("Frequency: " + str(int(frequency.total_seconds())) +"sec Interval: "+ str(int(interval.total_seconds()/60))+ " Window size: "+ str(windowSize) +" min")] = auc_value
                    else:
                        auc_scores_pr[str("Frequency: " + str(int(frequency.total_seconds())) +"sec Interval: "+ str(int(interval.total_seconds()/60))+ " Window size: "+ str(windowSize) +" min α: "+ str(alpha))] = auc_value
                    

    new_auc_scores =sorted(auc_scores.items(), key=itemgetter(1), reverse=True)[:100]
    print("ROC curve")
    pprint(new_auc_scores)
    new_auc_scores =sorted(auc_scores.items(), key=itemgetter(1), reverse=True)
    for i, tuple in enumerate(new_auc_scores):
        if tuple[0] == str("Frequency: " + str(60) +"sec Interval: "+ str(5)+ " Window size: "+ str(10) +" min α: "+ str(alpha)):
            print("5 min interval", i, tuple[1])
        elif tuple[0] == str("Frequency: " + str(60) +"sec Interval: "+ str(10)+ " Window size: "+ str(10) +" min α: "+ str(alpha)):
            print("10 min interval", i, tuple[1])
        elif tuple[0] == str("Frequency: " + str(60) +"sec Interval: "+ str(15)+ " Window size: "+ str(10) +" min α: "+ str(alpha)):
            print("15 min interval", i, tuple[1])

    new_auc_scores =sorted(auc_scores_pr.items(), key=itemgetter(1), reverse=True)[:100]
    print("PR curve")
    pprint(new_auc_scores)
    new_auc_scores =sorted(auc_scores_pr.items(), key=itemgetter(1), reverse=True)
    for i, tuple in enumerate(new_auc_scores):
        if tuple[0] == str("Frequency: " + str(60) +"sec Interval: "+ str(5)+ " Window size: "+ str(10) +" min α: "+ str(alpha)):
            print("5 min interval", i, tuple[1])
        elif tuple[0] == str("Frequency: " + str(60) +"sec Interval: "+ str(10)+ " Window size: "+ str(10) +" min α: "+ str(alpha)):
            print("10 min interval", i, tuple[1])
        elif tuple[0] == str("Frequency: " + str(60) +"sec Interval: "+ str(15)+ " Window size: "+ str(10) +" min α: "+ str(alpha)):
            print("15 min interval", i, tuple[1])

    '''axs.set_title("Roc curve")
    axs.set_xlabel("False Positive Rate")
    axs.set_ylabel("True Positive Rate")
    axs.tick_params(axis='both', which='major', labelsize=15)
    #fig.tight_layout()
    fig.legend()

    if not plotting.exists():
        plotting.mkdir(parents=True)
    fig.savefig("Plots/RocScores/" + str(y_field)+ ".pdf", dpi=300)
    
    plt.close(fig)'''

def makeHeatMap(y_field, dataSet, dataType, systemId, attackDate):
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

    frequencies = [timedelta(seconds=5),timedelta(seconds=10), timedelta(seconds=20), timedelta(seconds=30), timedelta(seconds=40), timedelta(seconds=50),timedelta(minutes=1)]
    dataArray = []
    x_labels = []
    y_labels = []
    for windowSize in range(2,21):
        for alpha in range(2, 16):
            row = []
            y_labels.append("α: "+ str(alpha) + ", Window size: "+ str(windowSize))
            for frequency in frequencies:
                for i in range(1,21):
                    interval = timedelta(minutes=i)
                    dataFile = str(q) + "/RocScores/" + str(y_field) +".alpha."+ str(alpha)+ ".windowSize."+ str(windowSize)+ "."+ str(int(frequency.total_seconds()))+ "secFrequency." +str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv"

                    if not Path(dataFile).exists():
                        print("no file", dataFile)
                        return
                    data = pd.read_csv(dataFile)
                    if len(data) == 0:
                        print("the file is empty")
                        return
                    tpr = pd.to_numeric(data["TPR"],errors='coerce')
                    fpr = pd.to_numeric(data["FPR"],errors='coerce')

                    truePositiveRate = []
                    falsePositiveRate = []
                    for i in range(len(tpr) -1, -1, -1):
                        truePositiveRate.append(tpr[i])
                        falsePositiveRate.append(fpr[i])
                    auc_value = auc(falsePositiveRate, truePositiveRate)
                
                    row.append(auc_value)
                    if len(dataArray) == 0:
                        x_labels.append("Frequency: " + str(int(frequency.total_seconds())) +"sec,\nInterval: "+ str(int(interval.total_seconds()/60)) +" min")
                    break
                break
            dataArray.append(row)
            
    print(len(y_labels))
    print(len(x_labels))
    print(len(dataArray[0]))
    colorsGood = ["#E9D4C7","#CB997E", "#3A2D32"]
    cmapGood = LinearSegmentedColormap.from_list("custom_cmap", colorsGood)
    fig, ax = plt.subplots(figsize=(100, 100))
    sns.heatmap(dataArray, annot=True, fmt=".3f", cmap=cmapGood, ax=ax, center=0.5, vmax=1, xticklabels=x_labels, yticklabels=y_labels)
    
    '''ax.set_xticklabels(x_labels, rotation = 30, ha='right')
    ax.set_yticklabels(y_labels, rotation = 30,ha='right')'''
    ax.set_title("AUC score")
    fig.tight_layout()
    #fig.legend()

    if not plotting.exists():
        plotting.mkdir(parents=True)
    fig.savefig("Plots/RocScores/HeatMap." + str(y_field)+ ".pdf", dpi=500)
    
    plt.close(fig)


def findBestROCandPRCurveTelemetry(y_field):
    json_file = open("ThresholdDecision/Entropy/Telemetry/AUC_roc.json", "r")
    auc_scores_roc = json.load(json_file)
    json_file.close()

    json_file = open("ThresholdDecision/Entropy/Telemetry/AUC_pr.json", "r")
    auc_scores_pr = json.load(json_file)
    json_file.close()

    auc_scores_roc = auc_scores_roc[y_field]
    auc_scores_pr = auc_scores_pr[y_field]

    new_auc_scores =sorted(auc_scores_roc.items(), key=itemgetter(1), reverse=True)[:10]
    print("ROC curve")
    pprint(new_auc_scores)
    new_auc_scores =sorted(auc_scores_roc.items(), key=itemgetter(1), reverse=True)
    '''print("My choice")
    for i, tuple in enumerate(new_auc_scores):
        if tuple[0] == str("Frequency: " + str(60) +"sec Interval: "+ str(5)+ " Window size: "+ str(10) +" min α: "+ str(10)):
            print("5 min interval", i, tuple[1])
        elif tuple[0] == str("Frequency: " + str(60) +"sec Interval: "+ str(10)+ " Window size: "+ str(10) +" min α: "+ str(10)):
            print("10 min interval", i, tuple[1])
        elif tuple[0] == str("Frequency: " + str(60) +"sec Interval: "+ str(15)+ " Window size: "+ str(10) +" min α: "+ str(10)):
            print("15 min interval", i, tuple[1])'''
    print("The worst selection")
    worst = sorted(auc_scores_roc.items(), key=itemgetter(1))[:10]
    pprint(worst)

    new_auc_scores =sorted(auc_scores_pr.items(), key=itemgetter(1), reverse=True)[:10]
    print("\nPR curve")
    pprint(new_auc_scores)
    new_auc_scores =sorted(auc_scores_pr.items(), key=itemgetter(1), reverse=True)
    '''print("My choice")
    for i, tuple in enumerate(new_auc_scores):
        #print(i, tuple)
        if tuple[0] == str("Frequency: " + str(60) +"sec Interval: "+ str(300)+ "sec Window size: "+ str(10) +" alpha: "+ str(10)):
            print("5 min interval", i, tuple[1])
        elif tuple[0] == str("Frequency: " + str(60) +"sec Interval: "+ str(600)+ "sec Window size: "+ str(10) +" alpha: "+ str(10)):
            print("10 min interval", i, tuple[1])
        elif tuple[0] == str("Frequency: " + str(60) +"sec Interval: "+ str(900)+ "sec Window size: "+ str(10) +" alpha: "+ str(10)):
            print("15 min interval", i, tuple[1])'''
    print("The worst selection")
    worst = sorted(auc_scores_pr.items(), key=itemgetter(1))[:10]
    pprint(worst)
systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]

attackDates = ["08.03.23", "17.03.23","24.03.23"]
intervals = [timedelta(minutes = 5),timedelta(minutes = 10), timedelta(minutes = 15)]
y_fields = ["dstEntropy", "dstEntropyRate","srcEntropy", "srcEntropyRate", "flowEntropy", "flowEntropyRate", "numberOfFlows", "icmpRatio", 
            "icmpPackets", "packetSizeEntropy", "packetSizeEntropyRate", "numberOfPackets", "numberOfBytes"]
y_field_names = ["DestinationIPEntropy", "DestinationIPEntropyRate","SourceIPEntropy", "SourceIPEntropyRate", "FlowEntropy", "FlowEntropyRate", "NumberOfFlows", "ICMPRatio", 
            "ICMPPackets", "PacketSizeEntropy", "PacketSizeEntropyRate", "Packets", "Bytes"]

y_fields = ["flowEntropy", "flowEntropyRate"]
y_field_names = ["Packets", "Bytes"]
'''for y_field in y_fields:
    makeROCcurve(y_field, "NetFlow", "Entropy", "hoytek-gw2", "24.03.23")

for y_field in y_fields:
    makeHeatMap(y_field, "NetFlow", "Entropy", "hoytek-gw2", "24.03.23")'''


y_fields = ["Entropy of ingress packet sizes", "Entropy of egress packet sizes", "Entropy rate of ingress packet sizes", "Entropy rate of egress packet sizes", "Number of ingress packets", "Number of egress packets", "Number of ingress bytes", "Number of egress bytes"]
y_fields = ["Entropy of ingress packet sizes", "Entropy of egress packet sizes", "Entropy rate of ingress packet sizes", "Entropy rate of egress packet sizes"]

for y_field in y_fields:
    print("\n", y_field)
    findBestROCandPRCurveTelemetry(y_field)