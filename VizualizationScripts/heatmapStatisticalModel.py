import math
from pathlib import Path
from matplotlib.colors import LinearSegmentedColormap
import pandas as pd
import numpy as np

import matplotlib.pyplot as plt
import seaborn as sns

from datetime import datetime, timedelta

from sklearn.metrics import auc

def makeHeatMapStatisticalModel(metric, attackDate):
    systems = ["trd-gw", "ifi2-gw5", "bergen-gw3", "tromso-gw5", "teknobyen-gw1", "teknobyen-gw2", "oslo-gw1", "hoytek-gw2", "hovedbygget-gw", "narvik-gw3", "narvik-gw4", "ma2-gw",  "tromso-fh-gw", "narvik-kv-gw", "stangnes-gw", "rodbergvn-gw2"]
    
    anonymizedSystems = ["AR1", "AR2", "AR3", "AR4", "VR", "CR1", "CR2", "CR3", "CR4", "CR5", "CR6", "CR7", "CR8", "CR9", "CR10", "CR11"]
    
    y_fields = ["egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets", "ingress_stats__if_1sec_pkts", "ingress_stats__if_1sec_octets", 
                "MaxVar.egress_queue_info__0__cur_buffer_occupancy", "MaxVar.egress_stats__if_1sec_pkts", "MaxVar.egress_stats__if_1sec_octets", "MaxVar.ingress_stats__if_1sec_pkts", "MaxVar.ingress_stats__if_1sec_octets"]


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
    p = Path('Detections' + fileString +"_5min_"+ metric)

    for systemId in systems:
        
        print(systemId)
        f1_scoresThisSystem = []
        precision_scoresThisSystem = []
        tpr_scoresThisSystem = []
        accuracy_scoresThisSystem = []
        fpr_scoresThisSystem = []
        fnr_scoresThisSystem = []
        
        for y_field in y_fields:
            truePositives = 0
            falsePositives = 0
            falseNegatives = 0
            trueNegatives = 0

            dataFile = str(p) + "/Threshold/Telemetry/Scores."+ y_field+ ".attack."+str(attackDate)+ "."+str(systemId)+ ".csv"

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

    '''transposed_f1_scores = np.transpose(f1_scores)
    transposed_precision_scores = np.transpose(precision_scores)
    transposed_tpr_scores = np.transpose(tpr_scores)
    transposed_accuracy_scores = np.transpose(accuracy_scores)
    transposed_fpr_scores = np.transpose(fpr_scores)
    transposed_fnr_scores = np.transpose(fnr_scores)'''
    colorsGood = ["#E9D4C7","#CB997E", "#3A2D32"]
    colorsBad = ["#3A2D32","#CB997E", "#E9D4C7"]
    '''colorsBad = ["#006400","#F6BE00", "#8B0000"]
    colorsGood = ["#8B0000","#F6BE00", "#006400"]'''

    x_labels = ["Deviation score for egress queue size", 
                "Deviation score for egress packets/s", 
                "Deviation score for egress bytes/s", 
                "Deviation score for ingress packets/s",
                "Deviation score for ingress bytes/s",
                "Deviation score for egress queue size\nusing maximum variance",
                "Deviation score for egress packets/s\nusing maximum variance",
                "Deviation score for egress bytes/s\nusing maximum variance",
                "Deviation score for ingress packets/s\nusing maximum variance",
                "Deviation score for ingress bytes/s\nusing maximum variance"]

    cmapGood = LinearSegmentedColormap.from_list("custom_cmap", colorsGood)
    cmapBad = LinearSegmentedColormap.from_list("custom_cmap", colorsBad)

    fig, ax = plt.subplots(figsize=(10, 10))
    sns.heatmap(f1_scores, annot=True, fmt=".3f", cmap=cmapGood, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(x_labels, rotation = 45, ha='right')
    ax.set_yticklabels(anonymizedSystems, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("F1-scores for empirical mean-variance model")
    fig.tight_layout()
    fig.savefig("Plots/Threshold/Attack"+ fileString+ "/Telemetry/Using."+metric+".F1.pdf", dpi=300)
    plt.close(fig)



    fig, ax = plt.subplots(figsize=(10, 10))
    sns.heatmap(precision_scores, annot=True, fmt=".3f", cmap=cmapGood, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(x_labels, rotation = 45, ha='right')
    ax.set_yticklabels(anonymizedSystems, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("Precision for empirical mean-variance model")
    fig.tight_layout()
    fig.savefig("Plots/Threshold/Attack"+ fileString+ "/Telemetry/Using."+metric+".Precision.pdf", dpi=300)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(10, 10))
    sns.heatmap(tpr_scores, annot=True, fmt=".3f", cmap=cmapGood, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(x_labels, rotation = 45, ha='right')
    ax.set_yticklabels(anonymizedSystems, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("TPR for empirical mean-variance model")
    fig.tight_layout()
    fig.savefig("Plots/Threshold/Attack"+ fileString+ "/Telemetry/Using."+metric+".TPR.pdf", dpi=300)
    plt.close(fig)


    fig, ax = plt.subplots(figsize=(10, 10))
    sns.heatmap(accuracy_scores, annot=True, fmt=".3f", cmap=cmapGood, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(x_labels, rotation = 45, ha='right')
    ax.set_yticklabels(anonymizedSystems, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("Accuracy for empirical mean-variance model")
    fig.tight_layout()
    fig.savefig("Plots/Threshold/Attack"+ fileString+ "/Telemetry/Using."+metric+".Accuracy.pdf", dpi=300)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(10, 10))
    sns.heatmap(fpr_scores, annot=True, fmt=".3f", cmap=cmapBad, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(x_labels, rotation = 45, ha='right')
    ax.set_yticklabels(anonymizedSystems, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("FPR for empirical mean-variance model")
    fig.tight_layout()
    fig.savefig("Plots/Threshold/Attack"+ fileString+ "/Telemetry/Using."+metric+".FPR.pdf", dpi=300)
    plt.close(fig)


    fig, ax = plt.subplots(figsize=(10, 10))
    sns.heatmap(fnr_scores, annot=True, fmt=".3f", cmap=cmapBad, ax=ax, center=0.5, vmax=1, vmin=0)
    
    ax.set_xticklabels(x_labels, rotation = 45, ha='right')
    ax.set_yticklabels(anonymizedSystems, rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("FNR for empirical mean-variance model")
    fig.tight_layout()
    fig.savefig("Plots/Threshold/Attack"+ fileString+ "/Telemetry/Using."+metric+".FNR.pdf", dpi=300)
    plt.close(fig)


def makeHeatMapStatisticalModelAUC(attackDate):
    systems = ["trd-gw", "ifi2-gw5", "bergen-gw3", "tromso-gw5", "teknobyen-gw1", "teknobyen-gw2", "oslo-gw1", "hoytek-gw2", "hovedbygget-gw", "narvik-gw3", "narvik-gw4", "ma2-gw",  "tromso-fh-gw", "narvik-kv-gw", "stangnes-gw", "rodbergvn-gw2"]
    
    anonymizedSystems = ["AR1", "AR2", "AR3", "AR4", "VR", "CR1", "CR2", "CR3", "CR4", "CR5", "CR6", "CR7", "CR8", "CR9", "CR10", "CR11"]
    
    y_fields = ["egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets", "ingress_stats__if_1sec_pkts", "ingress_stats__if_1sec_octets", "MaxVar.egress_queue_info__0__cur_buffer_occupancy", "MaxVar.egress_stats__if_1sec_pkts", "MaxVar.egress_stats__if_1sec_octets", "MaxVar.ingress_stats__if_1sec_pkts", "MaxVar.ingress_stats__if_1sec_octets"]


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
    decisionPath = Path('ThresholdDecision/Threshold/Telemetry') 
    plotPath = Path('Plots')

    if attackDate == "08.03.23":
        fileString = "0803"
        q = decisionPath /'Attack0803'
    elif attackDate == "17.03.23":
        fileString = "1703"
        q = decisionPath /'Attack1703' 
    elif attackDate == "24.03.23":
        fileString = "2403"
        q = decisionPath /'Attack2403' 

    colorCounter = 0
    data_roc = []
    data_pr = []
    
    for systemId in systems:
        row_roc = []
        row_pr = []
        print("\n")
        print(systemId)
        for y_field in y_fields:
            dataFile = str(q) + "/"+ y_field+ ".attack."+str(attackDate)+ "."+str(systemId)+ ".csv"

            if not Path(dataFile).exists():
                print("File doesnt exist", dataFile)
                row_roc.append(np.nan)
                row_pr.append(np.nan)
                continue
            data = pd.read_csv(dataFile)
            if len(data) == 0:
                print("Data is empty", dataFile)
                row_roc.append(np.nan)
                row_pr.append(np.nan)
                continue
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

            if len(row_pr) == 5:
                print(y_field)
                print(row_pr[0]-auc_value_pr)
            if len(row_pr) == 6:
                print(y_field)
                print(row_pr[1]-auc_value_pr)
            if len(row_pr) == 7:
                print(y_field)
                print(row_pr[2]-auc_value_pr)
            if len(row_pr) == 8:
                print(y_field)
                print(row_pr[3]-auc_value_pr)
            if len(row_pr) == 9:
                print(y_field)
                print(row_pr[4]-auc_value_pr)
            row_roc.append(auc_value_roc)
            row_pr.append(auc_value_pr)
        data_roc.append(row_roc)
        data_pr.append(row_pr)

    x_labels = ["Deviation score for egress queue size", 
                "Deviation score for egress packets/s", 
                "Deviation score for egress bytes/s", 
                "Deviation score for ingress packets/s",
                "Deviation score for ingress bytes/s",
                "Deviation score for egress queue size\nusing maximum variance",
                "Deviation score for egress packets/s\nusing maximum variance",
                "Deviation score for egress bytes/s\nusing maximum variance",
                "Deviation score for ingress packets/s\nusing maximum variance",
                "Deviation score for ingress bytes/s\nusing maximum variance"]

    '''colorsGood = ["#E9D4C7","#CB997E", "#3A2D32"]
    cmapGood = LinearSegmentedColormap.from_list("custom_cmap", colorsGood)
    fig, axs = plt.subplots(figsize=(10, 10))
    sns.heatmap(data_pr, annot=True, fmt=".3f", cmap=cmapGood, ax=axs, center=0.5, vmax=1, vmin=0, xticklabels=x_labels, yticklabels=anonymizedSystems)


    axs.set_title("Area under precision-recall curve", fontsize=15)
    axs.set_xticklabels(x_labels, rotation = 45, ha='right')
    axs.set_yticklabels(anonymizedSystems, rotation = 0,ha='right')
    axs.tick_params(axis='both', which='major', labelsize=10)
    fig.tight_layout()

    fig.savefig("Plots/Threshold/Attack"+ fileString+ "/Telemetry/PRHeatmap.pdf", dpi=300)
    plt.close(fig)

    fig, axs = plt.subplots(figsize=(10, 10))
    sns.heatmap(data_roc, annot=True, fmt=".3f", cmap=cmapGood, ax=axs, center=0.5, vmax=1, vmin=0, xticklabels=x_labels, yticklabels=anonymizedSystems)


    axs.set_title("Area under receiver operating characteristic curve", fontsize=15)
    axs.set_xticklabels(x_labels, rotation = 45, ha='right')
    axs.set_yticklabels(anonymizedSystems, rotation = 0,ha='right')
    axs.tick_params(axis='both', which='major', labelsize=10)
    fig.tight_layout()

    fig.savefig("Plots/Threshold/Attack"+ fileString+ "/Telemetry/ROCHeatmap.pdf", dpi=300)
    plt.close(fig)'''
    

makeHeatMapStatisticalModel( "F1", "24.03.23")
#makeHeatMapStatisticalModelAUC("24.03.23")