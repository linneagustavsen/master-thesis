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
    fig, axs = plt.subplots(1, 1, figsize=(7, 7))
    cmap = get_cmap(5600)
    colorCounter = 0
    frequencies = [timedelta(seconds=5),timedelta(seconds=10), timedelta(seconds=20), timedelta(seconds=30), timedelta(seconds=40), timedelta(seconds=50),timedelta(minutes=1)]
    for frequency in frequencies:
        for i in range(1,21):
            interval = timedelta(minutes=i)
            for alpha in range(2, 16):
                for windowSize in range(2,21):
                    dataFile = str(q) + "/RocScores/" + str(y_field) +".alpha."+ str(alpha)+ ".windowSize."+ str(windowSize)+ "."+ str(int(frequency.total_seconds()))+ "secFrequency." +str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv"

                    if not Path(dataFile).exists():
                        plt.close(fig)
                        print("no file", dataFile)
                        return
                    data = pd.read_csv(dataFile)
                    if len(data) == 0:
                        plt.close(fig)
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
                
                    axs.plot(falsePositiveRate ,truePositiveRate, color=cmap(colorCounter), label="Frequency: " + str(int(frequency.total_seconds())) +"sec, Interval: "+ str(int(interval.total_seconds()/60)) +" min, α: "+ str(alpha) + ", Window size: "+ str(windowSize) + ", AUC=%.3f"%auc_value)
                    colorCounter += 1
                break
            break
        break
    '''cmap = get_cmap(19)
    colorCounter = 0
    frequency= timedelta(seconds=5)
    interval = timedelta(minutes=1)
    alpha = 2
    for windowSize in range(2,21):
        dataFile = str(q) + "/RocScores/" + str(y_field) +".alpha."+ str(alpha)+ ".windowSize."+ str(windowSize)+ "."+ str(int(frequency.total_seconds()))+ "secFrequency." +str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv"

        if not Path(dataFile).exists():
            plt.close(fig)
            print("no file")
            return
        data = pd.read_csv(dataFile)
        if len(data) == 0:
            plt.close(fig)
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
    
        axs.plot(falsePositiveRate ,truePositiveRate, color=cmap(colorCounter), label="Window size: "+ str(windowSize) +" min\nAUC=%.3f"%auc_value)
        colorCounter += 1'''
    axs.set_title("Roc curve")
    axs.set_xlabel("False Positive Rate")
    axs.set_ylabel("True Positive Rate")
    axs.tick_params(axis='both', which='major', labelsize=15)
    #fig.tight_layout()
    fig.legend()

    if not plotting.exists():
        plotting.mkdir(parents=True)
    fig.savefig("Plots/RocScores/" + str(y_field)+ ".png", dpi=500)
    
    plt.close(fig)

systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]

attackDates = ["08.03.23", "17.03.23","24.03.23"]
intervals = [timedelta(minutes = 5),timedelta(minutes = 10), timedelta(minutes = 15)]
y_fields = ["dstEntropy", "dstEntropyRate","srcEntropy", "srcEntropyRate", "flowEntropy", "flowEntropyRate", "numberOfFlows", "icmpRatio", 
            "icmpPackets", "packetSizeEntropy", "packetSizeEntropyRate", "numberOfPackets", "numberOfBytes", "SYN.dstEntropy", "SYN.srcEntropy", "SYN.flowEntropy"]
y_fields = ["dstEntropy", "dstEntropyRate","srcEntropy", "srcEntropyRate", "flowEntropy", "flowEntropyRate", "numberOfFlows", "icmpRatio", 
            "icmpPackets", "packetSizeEntropy", "packetSizeEntropyRate", "numberOfPackets", "numberOfBytes"]
y_field_names = ["DestinationIPEntropy", "DestinationIPEntropyRate","SourceIPEntropy", "SourceIPEntropyRate", "FlowEntropy", "FlowEntropyRate", "NumberOfFlows", "ICMPRatio", 
            "ICMPPackets", "PacketSizeEntropy", "PacketSizeEntropyRate", "Packets", "Bytes"]
for y_field in y_fields:
    makeROCcurve(y_field, "NetFlow", "Entropy", "hoytek-gw2", "24.03.23")