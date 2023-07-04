from datetime import datetime, timedelta
from pathlib import Path
from matplotlib import pyplot as plt
from matplotlib.colors import LinearSegmentedColormap
import numpy as np
import pandas as pd
import seaborn as sns

def makeHeatMapTelemetry(y_fields, metrics, intervals, attackDate):
    systems = ["trd-gw", "ifi2-gw5", "bergen-gw3", "tromso-gw5", "teknobyen-gw1", "teknobyen-gw2", "oslo-gw1", "hoytek-gw2", "hovedbygget-gw", "narvik-gw3", "narvik-gw4", "ma2-gw",  "tromso-fh-gw", "narvik-kv-gw", "stangnes-gw", "rodbergvn-gw2"]
    
    anonymizedSystems = ["AR1", "AR2", "AR3", "AR4", "VR", "CR1", "CR2", "CR3", "CR4", "CR5", "CR6", "CR7", "CR8", "CR9", "CR10", "CR11"]
    
    

    if attackDate == "08.03.23":
        fileString = "0803"
        startTime = datetime.strptime("2023-03-08 14:15:00", '%Y-%m-%d %H:%M:%S')
        stopTime = datetime.strptime("2023-03-08 16:00:00", '%Y-%m-%d %H:%M:%S')
    elif attackDate == "17.03.23":
        fileString="1703"
        startTime = datetime.strptime("2023-03-17 11:00:00", '%Y-%m-%d %H:%M:%S')
        stopTime = datetime.strptime("2023-03-17 13:00:00", '%Y-%m-%d %H:%M:%S')
    elif attackDate == "24.03.23":
        fileString = "2403"
        startTime = datetime.strptime("2023-03-24 14:00:00", '%Y-%m-%d %H:%M:%S')
        stopTime = datetime.strptime("2023-03-24 18:00:00", '%Y-%m-%d %H:%M:%S')
    f1_scores = []
    precision_scores = []
    tpr_scores = []
    accuracy_scores = []
    fpr_scores = []
    fnr_scores = []
    systemCounter =0 

    for systemId in systems:
        
        print(systemId)
        f1_scoresThisSystem = []
        precision_scoresThisSystem = []
        tpr_scoresThisSystem = []
        accuracy_scoresThisSystem = []
        fpr_scoresThisSystem = []
        fnr_scoresThisSystem = []
        for metric in metrics:
            for interval in intervals:
                for y_field in y_fields:
                    truePositives = 0
                    falsePositives = 0
                    falseNegatives = 0
                    trueNegatives = 0

                    if interval == timedelta(minutes=5):
                        p = Path('Detections' + fileString + "_5min_" + metric)
                    elif interval == timedelta(minutes=10):
                        p = Path('Detections' + fileString + "_10min_" + metric)
                    if interval == timedelta(minutes=15):
                        p = Path('Detections' + fileString + "_15min_" + metric)
                    dataFile = str(p) + "/Entropy/Telemetry/Scores."+ y_field+ "."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv"

                    if not Path(dataFile).exists():
                        print("File doesnt exist", dataFile)
                        f1_scoresThisSystem.append(np.nan)
                        precision_scoresThisSystem.append(np.nan)
                        tpr_scoresThisSystem.append(np.nan)
                        accuracy_scoresThisSystem.append(np.nan)
                        fpr_scoresThisSystem.append(np.nan)
                        fnr_scoresThisSystem.append(np.nan)
                        continue
                
                    data = pd.read_csv(dataFile)
                
                    if len(data) != 0:
                        truePositives += data["TP"][0]
                        falsePositives += data["FP"][0]
                        trueNegatives += data["TN"][0]
                        falseNegatives += data["FN"][0]

                    
                    if falsePositives == 0 and trueNegatives == 0 and truePositives == 0 and falseNegatives == 0:
                        print("all where 0")
                        f1_scoresThisSystem.append(np.nan)
                        precision_scoresThisSystem.append(np.nan)
                        tpr_scoresThisSystem.append(np.nan)
                        accuracy_scoresThisSystem.append(np.nan)
                        fpr_scoresThisSystem.append(np.nan)
                        fnr_scoresThisSystem.append(np.nan)
                    else:
                        print(truePositives, falsePositives, trueNegatives, falseNegatives)
                        accuracy = (truePositives + trueNegatives)/(truePositives+trueNegatives+falsePositives+falseNegatives)
                        if falsePositives != 0 or trueNegatives != 0:
                            fpr = falsePositives/(falsePositives + trueNegatives)
                        else:
                            fpr = np.nan
                        if falseNegatives != 0  or truePositives != 0:
                            fnr = falseNegatives/(falseNegatives + truePositives)
                        else:
                            fnr = np.nan
                        if truePositives != 0 or falsePositives != 0:
                            precision = truePositives/(truePositives+falsePositives)
                        else:
                            precision = np.nan
                        if  falseNegatives != 0 or truePositives != 0:
                            recall = truePositives/(truePositives+ falseNegatives)
                        else:
                            recall = np.nan
                        if truePositives != 0 or falsePositives!= 0 or falseNegatives != 0:
                            f1 =2*truePositives/(2*truePositives+falsePositives+falseNegatives)
                        else:
                            f1 = np.nan

                        f1_scoresThisSystem.append(f1)
                        precision_scoresThisSystem.append(precision)
                        tpr_scoresThisSystem.append(recall)
                        accuracy_scoresThisSystem.append(accuracy)
                        fpr_scoresThisSystem.append(fpr)
                        fnr_scoresThisSystem.append(fnr)

        f1_scores.append(f1_scoresThisSystem)
        precision_scores.append(precision_scoresThisSystem)
        tpr_scores.append(tpr_scoresThisSystem)
        accuracy_scores.append(accuracy_scoresThisSystem)
        fpr_scores.append(fpr_scoresThisSystem)
        fnr_scores.append(fnr_scoresThisSystem)

    f1_scores = np.transpose(f1_scores)
    precision_scores = np.transpose(precision_scores)
    tpr_scores = np.transpose(tpr_scores)
    accuracy_scores = np.transpose(accuracy_scores)
    fpr_scores = np.transpose(fpr_scores)
    fnr_scores = np.transpose(fnr_scores)
    colorsGood = ["#E9D4C7","#CB997E", "#3A2D32"]
    colorsBad = ["#3A2D32","#CB997E", "#E9D4C7"]
    '''colorsBad = ["#006400","#F6BE00", "#8B0000"]
    colorsGood = ["#8B0000","#F6BE00", "#006400"]'''
    y_labels = ["Entropy of ingress packet sizes in a\n5 min window, using TPR", 
                "Entropy of egress packet sizes in a\n5 min window, using TPR",
                "Entropy rate of ingress packet sizes in a\n5 min window, using TPR", 
                "Entropy rate of egress packet sizes in a\n5 min window, using TPR", 

                "Entropy of ingress packet sizes in a\n10 min window, using TPR", 
                "Entropy of egress packet sizes in a\n10 min window, using TPR",
                "Entropy rate of ingress packet sizes in a\n10 min window, using TPR", 
                "Entropy rate of egress packet sizes in a\n10 min window, using TPR", 

                "Entropy of ingress packet sizes in a\n15 min window, using TPR", 
                "Entropy of egress packet sizes in a\n15 min window, using TPR",
                "Entropy rate of ingress packet sizes in a\n15 min window, using TPR", 
                "Entropy rate of egress packet sizes in a\n15 min window, using TPR", 
                
                "Entropy of ingress packet sizes in a\n5 min window, using F1", 
                "Entropy of egress packet sizes in a\n5 min window, using F1",
                "Entropy rate of ingress packet sizes in a\n5 min window, using F1", 
                "Entropy rate of egress packet sizes in a\n5 min window, using F1", 

                "Entropy of ingress packet sizes in a\n10 min window, using F1", 
                "Entropy of egress packet sizes in a\n10 min window, using F1",
                "Entropy rate of ingress packet sizes in a\n10 min window, using F1", 
                "Entropy rate of egress packet sizes in a\n10 min window, using F1", 

                "Entropy of ingress packet sizes in a\n15 min window, using F1", 
                "Entropy of egress packet sizes in a\n15 min window, using F1",
                "Entropy rate of ingress packet sizes in a\n15 min window, using F1", 
                "Entropy rate of egress packet sizes in a\n15 min window, using F1", ]

    cmapGood = LinearSegmentedColormap.from_list("custom_cmap", colorsGood)
    cmapBad = LinearSegmentedColormap.from_list("custom_cmap", colorsBad)
    print(len(f1_scores))
    fig, ax = plt.subplots(figsize=(15, 15))
    sns.heatmap(f1_scores, annot=True, fmt=".3f", cmap=cmapGood, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(anonymizedSystems, rotation = 0, ha='center')
    ax.set_yticklabels(y_labels, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("F1-scores for entropy and entropy rate of packet sizes")
    fig.tight_layout()
    fig.savefig("Plots/Entropy/Attack"+ fileString+ "/Telemetry/PacketSizes.F1.pdf", dpi=300)
    plt.close(fig)



    fig, ax = plt.subplots(figsize=(15, 15))
    sns.heatmap(precision_scores, annot=True, fmt=".3f", cmap=cmapGood, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(anonymizedSystems, rotation = 0, ha='center')
    ax.set_yticklabels(y_labels, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("Precision for entropy and entropy rate of packet sizes")
    fig.tight_layout()
    fig.savefig("Plots/Entropy/Attack"+ fileString+ "/Telemetry/PacketSizes.Precision.pdf", dpi=300)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(15, 15))
    sns.heatmap(tpr_scores, annot=True, fmt=".3f", cmap=cmapGood, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(anonymizedSystems, rotation = 0, ha='center')
    ax.set_yticklabels(y_labels, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("TPR for entropy and entropy rate of packet sizes")
    fig.tight_layout()
    fig.savefig("Plots/Entropy/Attack"+ fileString+ "/Telemetry/PacketSizes.TPR.pdf", dpi=300)
    plt.close(fig)


    fig, ax = plt.subplots(figsize=(15, 15))
    sns.heatmap(accuracy_scores, annot=True, fmt=".3f", cmap=cmapGood, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(anonymizedSystems, rotation = 0, ha='center')
    ax.set_yticklabels(y_labels, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("Accuracy for entropy and entropy rate of packet sizes")
    fig.tight_layout()
    fig.savefig("Plots/Entropy/Attack"+ fileString+ "/Telemetry/PacketSizes.Accuracy.pdf", dpi=300)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(15, 15))
    sns.heatmap(fpr_scores, annot=True, fmt=".3f", cmap=cmapBad, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(anonymizedSystems, rotation = 0, ha='center')
    ax.set_yticklabels(y_labels, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("FPR for entropy and entropy rate of packet sizes")
    fig.tight_layout()
    fig.savefig("Plots/Entropy/Attack"+ fileString+ "/Telemetry/PacketSizes.FPR.pdf", dpi=300)
    plt.close(fig)


    fig, ax = plt.subplots(figsize=(15, 15))
    sns.heatmap(fnr_scores, annot=True, fmt=".3f", cmap=cmapBad, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(anonymizedSystems, rotation = 0, ha='center')
    ax.set_yticklabels(y_labels, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("FNR for entropy and entropy rate of packet sizes")
    fig.tight_layout()
    fig.savefig("Plots/Entropy/Attack"+ fileString+ "/Telemetry/PacketSizes.FNR.pdf", dpi=300)
    plt.close(fig)

intervals = [timedelta(minutes = 5),timedelta(minutes = 10), timedelta(minutes = 15)]
y_fields= ["EntropyPacketSize_ingress","EntropyPacketSize_egress","EntropyRatePacketSize_ingress","EntropyRatePacketSize_egress"]
makeHeatMapTelemetry(y_fields, ["TPR", "F1"], intervals, "24.03.23")