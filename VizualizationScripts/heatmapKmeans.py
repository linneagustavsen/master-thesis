import math
from pathlib import Path
from matplotlib.colors import LinearSegmentedColormap
import pandas as pd
import numpy as np

import matplotlib.pyplot as plt
import seaborn as sns

from datetime import datetime, timedelta
def makeHeatMapKmeansBoth(y_fields, intervals,metric, dataType, attackDate):
    systems = ["trd-gw", "ifi2-gw5", "bergen-gw3", "tromso-gw5", "teknobyen-gw1",  "hoytek-gw2"]
    
    anonymizedSystems = ["AR1", "AR2", "AR3", "AR4", "VR", "CR3"]

    if attackDate == "08.03.23":
        fileString = "0803"
    elif attackDate == "17.03.23":
        fileString = "1703"
    elif attackDate == "24.03.23":
        fileString = "2403"

    f1_scores = []
    precision_scores = []
    tpr_scores = []
    accuracy_scores = []
    fpr_scores = []
    fnr_scores = []
    systemCounter =0 
    totalF1Score = 0
    total_precision_Score = 0
    total_tpr_Score = 0
    total_accuracy_Score = 0
    total_fpr_Score = 0
    total_fnr_Score = 0
    for systemId in systems:
        
        #print(systemId)
        f1_scoresThisSystem = []
        precision_scoresThisSystem = []
        tpr_scoresThisSystem = []
        accuracy_scoresThisSystem = []
        fpr_scoresThisSystem = []
        fnr_scoresThisSystem = []
        for y_field in y_fields:
            if y_field == "Fields":
                p = Path('Detections' + fileString + "_5min_" + metric)
                
                truePositives = 0
                falsePositives = 0
                falseNegatives = 0
                trueNegatives = 0

                dataFile = str(p) + "/"+dataType+"/NetFlow/Scores."+y_field+".attack."+str(attackDate)+ "."+str(systemId)+ ".csv"

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
                    #print(truePositives, falsePositives, trueNegatives, falseNegatives)
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
                    totalF1Score += f1
                    total_precision_Score += precision
                    total_tpr_Score += recall
                    total_accuracy_Score += accuracy
                    total_fpr_Score += fpr
                    total_fnr_Score += fnr
                    f1_scoresThisSystem.append(f1)
                    precision_scoresThisSystem.append(precision)
                    tpr_scoresThisSystem.append(recall)
                    accuracy_scoresThisSystem.append(accuracy)
                    fpr_scoresThisSystem.append(fpr)
                    fnr_scoresThisSystem.append(fnr)

            else:
                for interval in intervals:
                    if interval == timedelta(minutes=5):
                        p = Path('Detections' + fileString + "_5min_" + metric)
                    elif interval == timedelta(minutes=10):
                        p = Path('Detections' + fileString + "_10min_" + metric)
                    if interval == timedelta(minutes=15):
                        p = Path('Detections' + fileString + "_15min_" + metric)
                    truePositives = 0
                    falsePositives = 0
                    falseNegatives = 0
                    trueNegatives = 0

                    dataFile = str(p) + "/"+dataType+"/NetFlow/Scores."+y_field+"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv"

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
                        #print(truePositives, falsePositives, trueNegatives, falseNegatives)
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
                        totalF1Score += f1
                        total_precision_Score += precision
                        total_tpr_Score += recall
                        total_accuracy_Score += accuracy
                        total_fpr_Score += fpr
                        total_fnr_Score += fnr
                        f1_scoresThisSystem.append(f1)
                        precision_scoresThisSystem.append(precision)
                        tpr_scoresThisSystem.append(recall)
                        accuracy_scoresThisSystem.append(accuracy)
                        fpr_scoresThisSystem.append(fpr)
                        fnr_scoresThisSystem.append(fnr)
            
        for y_field in y_fields:
            if y_field == "Fields":
                p = Path('Detections' + fileString + "_5min_" + metric)
                
                truePositives = 0
                falsePositives = 0
                falseNegatives = 0
                trueNegatives = 0

                dataFile = str(p) + "/"+dataType+"/Telemetry/Scores."+y_field+".attack."+str(attackDate)+ "."+str(systemId)+ ".csv"

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
                    #print(truePositives, falsePositives, trueNegatives, falseNegatives)
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
                    totalF1Score += f1
                    total_precision_Score += precision
                    total_tpr_Score += recall
                    total_accuracy_Score += accuracy
                    total_fpr_Score += fpr
                    total_fnr_Score += fnr
                    f1_scoresThisSystem.append(f1)
                    precision_scoresThisSystem.append(precision)
                    tpr_scoresThisSystem.append(recall)
                    accuracy_scoresThisSystem.append(accuracy)
                    fpr_scoresThisSystem.append(fpr)
                    fnr_scoresThisSystem.append(fnr)

            else:
                for interval in intervals:
                    if interval == timedelta(minutes=5):
                        p = Path('Detections' + fileString + "_5min_" + metric)
                    elif interval == timedelta(minutes=10):
                        p = Path('Detections' + fileString + "_10min_" + metric)
                    if interval == timedelta(minutes=15):
                        p = Path('Detections' + fileString + "_15min_" + metric)
                    truePositives = 0
                    falsePositives = 0
                    falseNegatives = 0
                    trueNegatives = 0

                    dataFile = str(p) + "/"+dataType+"/Telemetry/Scores."+y_field+"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv"

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
                        #print(truePositives, falsePositives, trueNegatives, falseNegatives)
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
                        totalF1Score += f1
                        total_precision_Score += precision
                        total_tpr_Score += recall
                        total_accuracy_Score += accuracy
                        total_fpr_Score += fpr
                        total_fnr_Score += fnr
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

    y_labels = [
                "Fields, NetFlow", 
                "Entropy in a 5 min window, NetFlow",
                "Entropy in a 10 min window, NetFlow",
                "Entropy in a 15 min window, NetFlow",
                "Combined in a 5 min window, NetFlow",
                "Combined in a 10 min window, NetFlow",
                "Combined in a 15 min window, NetFlow",
                
                "Fields, Telemetry", 
                "Entropy in a 5 min window, Telemetry",
                "Entropy in a 10 min window, Telemetry",
                "Entropy in a 15 min window, Telemetry",
                "Combined in a 5 min window, Telemetry",
                "Combined in a 10 min window, Telemetry",
                "Combined in a 15 min window, Telemetry"]
    
    print("Average")
    print(totalF1Score/len(y_labels))
    print(total_precision_Score/len(y_labels))
    print(total_tpr_Score/len(y_labels))
    print(total_accuracy_Score/len(y_labels))
    print(total_fpr_Score/len(y_labels))
    print(total_fnr_Score/len(y_labels))

    cmapGood = LinearSegmentedColormap.from_list("custom_cmap", colorsGood)
    cmapBad = LinearSegmentedColormap.from_list("custom_cmap", colorsBad)

    fig, ax = plt.subplots(figsize=(10, 10))
    sns.heatmap(f1_scores, annot=True, fmt=".3f", cmap=cmapGood, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(anonymizedSystems, rotation = 0, ha='center')
    ax.set_yticklabels(y_labels, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("F1-scores for K-means clustering")
    fig.tight_layout()
    fig.savefig("Plots/"+dataType+"/Attack"+ fileString+ "/F1.pdf", dpi=300)
    plt.close(fig)



    fig, ax = plt.subplots(figsize=(10, 10))
    sns.heatmap(precision_scores, annot=True, fmt=".3f", cmap=cmapGood, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(anonymizedSystems, rotation = 0, ha='center')
    ax.set_yticklabels(y_labels, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("Precision for K-means clustering")
    fig.tight_layout()
    fig.savefig("Plots/"+dataType+"/Attack"+ fileString+ "/Precision.pdf", dpi=300)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(10, 7))
    sns.heatmap(tpr_scores, annot=True, fmt=".3f", cmap=cmapGood, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(anonymizedSystems, rotation = 0, ha='center')
    ax.set_yticklabels(y_labels, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("TPR for K-means clustering")
    fig.tight_layout()
    fig.savefig("Plots/"+dataType+"/Attack"+ fileString+ "/TPR.pdf", dpi=300)
    plt.close(fig)


    fig, ax = plt.subplots(figsize=(10, 10))
    sns.heatmap(accuracy_scores, annot=True, fmt=".3f", cmap=cmapGood, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(anonymizedSystems, rotation = 0, ha='center')
    ax.set_yticklabels(y_labels, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("Accuracy for K-means clustering")
    fig.tight_layout()
    fig.savefig("Plots/"+dataType+"/Attack"+ fileString+ "/Accuracy.pdf", dpi=300)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(10, 10))
    sns.heatmap(fpr_scores, annot=True, fmt=".3f", cmap=cmapBad, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(anonymizedSystems, rotation = 0, ha='center')
    ax.set_yticklabels(y_labels, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("FPR for K-means clustering")
    fig.tight_layout()
    fig.savefig("Plots/"+dataType+"/Attack"+ fileString+ "/FPR.pdf", dpi=300)
    plt.close(fig)


    fig, ax = plt.subplots(figsize=(10, 10))
    sns.heatmap(fnr_scores, annot=True, fmt=".3f", cmap=cmapBad, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(anonymizedSystems, rotation = 0, ha='center')
    ax.set_yticklabels(y_labels, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("FNR for K-means clustering")
    fig.tight_layout()
    fig.savefig("Plots/"+dataType+"/Attack"+ fileString+ "/FNR.pdf", dpi=300)
    plt.close(fig)


def makeHeatMapKmeans(y_fields, intervals,metric, dataType, dataset, attackDate):
    if dataset == "NetFlow":
        systems = ["trd-gw", "ifi2-gw5", "bergen-gw3", "tromso-gw5", "teknobyen-gw1",  "hoytek-gw2"]
    
        anonymizedSystems = ["AR1", "AR2", "AR3", "AR4", "VR", "CR3"]
    else:
        systems = ["trd-gw", "ifi2-gw5", "bergen-gw3", "tromso-gw5", "teknobyen-gw1", "teknobyen-gw2", "oslo-gw1", "hoytek-gw2", "hovedbygget-gw", "narvik-gw3", "narvik-gw4", "ma2-gw",  "tromso-fh-gw", "narvik-kv-gw", "stangnes-gw", "rodbergvn-gw2"]
    
        anonymizedSystems = ["AR1", "AR2", "AR3", "AR4", "VR", "CR1", "CR2", "CR3", "CR4", "CR5", "CR6", "CR7", "CR8", "CR9", "CR10", "CR11"]
    if attackDate == "08.03.23":
        fileString = "0803"
    elif attackDate == "17.03.23":
        fileString = "1703"
    elif attackDate == "24.03.23":
        fileString = "2403"

    f1_scores = []
    precision_scores = []
    tpr_scores = []
    accuracy_scores = []
    fpr_scores = []
    fnr_scores = []
    systemCounter =0 
    totalF1Score = 0
    total_precision_Score = 0
    total_tpr_Score = 0
    total_accuracy_Score = 0
    total_fpr_Score = 0
    total_fnr_Score = 0
    for systemId in systems:
        
        #print(systemId)
        f1_scoresThisSystem = []
        precision_scoresThisSystem = []
        tpr_scoresThisSystem = []
        accuracy_scoresThisSystem = []
        fpr_scoresThisSystem = []
        fnr_scoresThisSystem = []
            
        for y_field in y_fields:
            if y_field == "Fields":
                p = Path('Detections' + fileString + "_5min_" + metric)
                
                truePositives = 0
                falsePositives = 0
                falseNegatives = 0
                trueNegatives = 0

                dataFile = str(p) + "/"+dataType+"/Telemetry/Scores."+y_field+".attack."+str(attackDate)+ "."+str(systemId)+ ".csv"

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
                    #print(truePositives, falsePositives, trueNegatives, falseNegatives)
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
                    totalF1Score += f1
                    total_precision_Score += precision
                    total_tpr_Score += recall
                    total_accuracy_Score += accuracy
                    total_fpr_Score += fpr
                    total_fnr_Score += fnr
                    f1_scoresThisSystem.append(f1)
                    precision_scoresThisSystem.append(precision)
                    tpr_scoresThisSystem.append(recall)
                    accuracy_scoresThisSystem.append(accuracy)
                    fpr_scoresThisSystem.append(fpr)
                    fnr_scoresThisSystem.append(fnr)

            else:
                for interval in intervals:
                    if interval == timedelta(minutes=5):
                        p = Path('Detections' + fileString + "_5min_" + metric)
                    elif interval == timedelta(minutes=10):
                        p = Path('Detections' + fileString + "_10min_" + metric)
                    if interval == timedelta(minutes=15):
                        p = Path('Detections' + fileString + "_15min_" + metric)
                    truePositives = 0
                    falsePositives = 0
                    falseNegatives = 0
                    trueNegatives = 0

                    dataFile = str(p) + "/"+dataType+"/Telemetry/Scores."+y_field+"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv"

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
                        #print(truePositives, falsePositives, trueNegatives, falseNegatives)
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
                        totalF1Score += f1
                        total_precision_Score += precision
                        total_tpr_Score += recall
                        total_accuracy_Score += accuracy
                        total_fpr_Score += fpr
                        total_fnr_Score += fnr
                        f1_scoresThisSystem.append(f1)
                        precision_scoresThisSystem.append(precision)
                        tpr_scoresThisSystem.append(recall)
                        accuracy_scoresThisSystem.append(accuracy)
                        fpr_scoresThisSystem.append(fpr)
                        fnr_scoresThisSystem.append(fnr)

        print("\nAverage for", systemId)
        #print("F1:", totalF1Score/7)
        #print("Precision:", total_precision_Score/7)
        #print("TPR:", total_tpr_Score/7)
        #print("Accuracy:", total_accuracy_Score/7)
        #print("FPR:", total_fpr_Score/7)
        print("TNR:", total_fnr_Score/7)
        
        totalF1Score = 0
        total_precision_Score = 0
        total_tpr_Score = 0
        total_accuracy_Score = 0
        total_fpr_Score = 0
        total_fnr_Score = 0

        f1_scores.append(f1_scoresThisSystem)
        precision_scores.append(precision_scoresThisSystem)
        tpr_scores.append(tpr_scoresThisSystem)
        accuracy_scores.append(accuracy_scoresThisSystem)
        fpr_scores.append(fpr_scoresThisSystem)
        fnr_scores.append(fnr_scoresThisSystem)
    print(f1_scores)
    '''f1_scores = np.transpose(f1_scores)
    precision_scores = np.transpose(precision_scores)
    tpr_scores = np.transpose(tpr_scores)
    accuracy_scores = np.transpose(accuracy_scores)
    fpr_scores = np.transpose(fpr_scores)
    fnr_scores = np.transpose(fnr_scores)'''
    colorsGood = ["#E9D4C7","#CB997E", "#3A2D32"]
    colorsBad = ["#3A2D32","#CB997E", "#E9D4C7"]
    '''colorsBad = ["#006400","#F6BE00", "#8B0000"]
    colorsGood = ["#8B0000","#F6BE00", "#006400"]'''

    y_labels = ["Fields", 
                "Entropy in a 5 min window",
                "Entropy in a 10 min window",
                "Entropy in a 15 min window",
                "Combined in a 5 min window",
                "Combined in a 10 min window",
                "Combined in a 15 min window"]
    

    '''cmapGood = LinearSegmentedColormap.from_list("custom_cmap", colorsGood)
    cmapBad = LinearSegmentedColormap.from_list("custom_cmap", colorsBad)

    fig, ax = plt.subplots(figsize=(10, 10))
    sns.heatmap(f1_scores, annot=True, fmt=".3f", cmap=cmapGood, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(y_labels, rotation = 30, ha='right')
    ax.set_yticklabels(anonymizedSystems, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("F1-scores for K-means clustering")
    fig.tight_layout()
    fig.savefig("Plots/"+dataType+"/Attack"+ fileString+ "/"+ dataset+"/F1.pdf", dpi=300)
    plt.close(fig)



    fig, ax = plt.subplots(figsize=(10, 10))
    sns.heatmap(precision_scores, annot=True, fmt=".3f", cmap=cmapGood, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(y_labels, rotation = 30, ha='right')
    ax.set_yticklabels(anonymizedSystems, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("Precision for K-means clustering")
    fig.tight_layout()
    fig.savefig("Plots/"+dataType+"/Attack"+ fileString+ "/"+ dataset+"/Precision.pdf", dpi=300)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(10, 10))
    sns.heatmap(tpr_scores, annot=True, fmt=".3f", cmap=cmapGood, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(y_labels, rotation = 30, ha='right')
    ax.set_yticklabels(anonymizedSystems, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("TPR for K-means clustering")
    fig.tight_layout()
    fig.savefig("Plots/"+dataType+"/Attack"+ fileString+ "/"+ dataset+"/TPR.pdf", dpi=300)
    plt.close(fig)


    fig, ax = plt.subplots(figsize=(10, 10))
    sns.heatmap(accuracy_scores, annot=True, fmt=".3f", cmap=cmapGood, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(y_labels, rotation = 30, ha='right')
    ax.set_yticklabels(anonymizedSystems, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("Accuracy for K-means clustering")
    fig.tight_layout()
    fig.savefig("Plots/"+dataType+"/Attack"+ fileString+ "/"+ dataset+"/Accuracy.pdf", dpi=300)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(10, 10))
    sns.heatmap(fpr_scores, annot=True, fmt=".3f", cmap=cmapBad, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(y_labels, rotation = 30, ha='right')
    ax.set_yticklabels(anonymizedSystems, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("FPR for K-means clustering")
    fig.tight_layout()
    fig.savefig("Plots/"+dataType+"/Attack"+ fileString+ "/"+ dataset+"/FPR.pdf", dpi=300)
    plt.close(fig)


    fig, ax = plt.subplots(figsize=(10, 10))
    sns.heatmap(fnr_scores, annot=True, fmt=".3f", cmap=cmapBad, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(y_labels, rotation = 30, ha='right')
    ax.set_yticklabels(anonymizedSystems, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("FNR for K-means clustering")
    fig.tight_layout()
    fig.savefig("Plots/"+dataType+"/Attack"+ fileString+ "/"+ dataset+"/FNR.pdf", dpi=300)
    plt.close(fig)'''
y_fields = ["Fields", "Entropy", "Combined"]
intervals = [timedelta(minutes = 5),timedelta(minutes = 10), timedelta(minutes = 15)]

#makeHeatMapKmeansBoth(y_fields, intervals,"F1", "Kmeans", "24.03.23")
makeHeatMapKmeans(y_fields, intervals,"F1", "Kmeans", "Telemetry", "24.03.23")