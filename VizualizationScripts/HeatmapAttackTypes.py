from datetime import timedelta
import json
from pathlib import Path
from matplotlib.colors import LinearSegmentedColormap, ListedColormap, LogNorm
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import pandas as pd

def makeHeatMapAttackTypes(metrics, intervals, attackDate):
    if attackDate == "08.03.23":
        fileString = "0803"
    elif attackDate == "17.03.23":
        fileString = "1703"
    elif attackDate == "24.03.23":
        fileString = "2403"
        
    allAlerts = 0
    kmeansAlerts = 0
    routers = (
        "AR1",
        "AR2",
        "AR3",
        "AR4",
        "VR", 
        "CR3"
    )

    
    systems = ["trd-gw", "ifi2-gw5", "bergen-gw3", "tromso-gw5",  "teknobyen-gw1", "hoytek-gw2"]
    attackTypes = ["UDP Flood",
                       "SlowLoris", 
                       "Ping Flood", 
                       "Slow Read",
                       "Blacknurse",
                       "SYN Flood",
                       "R.U.D.Y",
                       "Xmas",
                       "UDP Flood and SlowLoris",
                       "Ping Flood and R.U.D.Y",
                       "All types"]
    
    precision_attackTypes = []
    f1_attackTypes = []
    accuracy_attackTypes = []
    tpr_attackTypes = []
    fpr_attackTypes = []
    fnr_attackTypes = []
    for attack in attackTypes:
        detectionMethods = {
        "Entropy of destination IP addresses": {"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Entropy of source IP addresses":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Entropy of bi-directional flows":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Entropy rate of destination IP addresses":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Entropy rate of source IP addresses":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Entropy rate of bi-directional flows":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},

        "Entropy of packet sizes":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Entropy rate of packet sizes":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},

        "Entropy of ingress packet sizes":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Entropy rate of ingress packet sizes":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Entropy of egress packet sizes":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Entropy rate of egress packet sizes":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        
        "Entropy of destination IP addresses with SYN flag":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Entropy of source IP addresses with SYN flag":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Entropy of bi-directional flows with SYN flag":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},

        "K-means with NetFlow header fields":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "K-means with NetFlow entropy metrics":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "K-means with NetFlow combined feature set":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},

        "K-means with telemetry measurements":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "K-means with telemetry entropy metrics":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "K-means with telemetry combined feature set":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},

        "Random Forest with NetFlow header fields":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Random Forest with NetFlow header fields without IPs":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Random Forest with NetFlow entropy metrics":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Random Forest with NetFlow combined feature set":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Random Forest with NetFlow combined feature set  without IPs":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},

        "Random Forest with telemetry measurements":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Random Forest with telemetry entropy metrics":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Random Forest with telemetry combined feature set":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},

        "Bytes in NetFlow records":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Packets in NetFlow records":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Bi-directional flows in NetFlow records":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},

        "Ingress bytes in telemetry measurements": {"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Ingress packets in telemetry measurements": {"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Egress bytes in telemetry measurements": {"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Egress packets in telemetry measurements": {"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},


        "Deviation score for egress queue size":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Deviation score for egress bytes/s":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Deviation score for egress packets/s":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Deviation score for ingress bytes/s":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Deviation score for ingress packets/s":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},

        "Deviation score for egress queue size using maximum variance":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Deviation score for egress bytes/s using maximum variance":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Deviation score for egress packets/s using maximum variance":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Deviation score for ingress bytes/s using maximum variance":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Deviation score for ingress packets/s using maximum variance":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},

        "ICMP destination unreachable packets":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "ICMP packets":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "ICMP ratio":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},

        "Xmas flows":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "SYN flows":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},

        "Top 20 flows":{"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},

        "Alert fusion: time": {"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Alert fusion: packet sizes": {"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Alert fusion: attack types": {"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        "Alert fusion: ranking": {"Precision":[], "TPR": [], "F1": [], "Accuracy": [], "FPR": [], "FNR": []},
        
        }
        for systemId in systems:
            for metric in metrics:
                for interval in intervals:
                    if interval == timedelta(minutes = 5):
                        windowSize = "5min"
                    elif interval == timedelta(minutes = 10):
                        windowSize = "10min"
                    elif interval == timedelta(minutes = 15):
                        windowSize = "15min"
                    p = Path('Detections' + fileString +"_"+ windowSize +"_"+ metric)
                    
                    paths = {
                        "Entropy of destination IP addresses": str(p) + "/Entropy/NetFlow/ScoresAttacks.DestinationIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".json",
                        "Entropy of source IP addresses": str(p) + "/Entropy/NetFlow/ScoresAttacks.SourceIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".json",
                        "Entropy of bi-directional flows": str(p) + "/Entropy/NetFlow/ScoresAttacks.FlowEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".json",
                        "Entropy rate of destination IP addresses": str(p) + "/Entropy/NetFlow/ScoresAttacks.DestinationIPEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".json",
                        "Entropy rate of source IP addresses": str(p) + "/Entropy/NetFlow/ScoresAttacks.SourceIPEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".json",
                        "Entropy rate of bi-directional flows":  str(p) + "/Entropy/NetFlow/ScoresAttacks.FlowEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".json",

                        "Entropy of packet sizes":  str(p) + "/Entropy/NetFlow/ScoresAttacks.PacketSizeEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".json",
                        "Entropy rate of packet sizes": str(p) + "/Entropy/NetFlow/ScoresAttacks.PacketSizeEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".json",

                        "Entropy of ingress packet sizes": str(p) + "/Entropy/Telemetry/ScoresAttacks.EntropyPacketSize_ingress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".json",
                        "Entropy rate of ingress packet sizes": str(p) + "/Entropy/Telemetry/ScoresAttacks.EntropyRatePacketSize_ingress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".json",
                        "Entropy of egress packet sizes": str(p) + "/Entropy/Telemetry/ScoresAttacks.EntropyPacketSize_egress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".json",
                        "Entropy rate of egress packet sizes": str(p) + "/Entropy/Telemetry/ScoresAttacks.EntropyRatePacketSize_egress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".json",
                        
                        "Entropy of destination IP addresses with SYN flag": str(p) + "/Entropy/NetFlow/ScoresAttacks.SYNDestinationIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".json",
                        "Entropy of source IP addresses with SYN flag": str(p) + "/Entropy/NetFlow/ScoresAttacks.SYNSourceIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".json",
                        "Entropy of bi-directional flows with SYN flag": str(p) + "/Entropy/NetFlow/ScoresAttacks.SYNFlowIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".json",

                        "K-means with NetFlow header fields": str(p) + "/Kmeans/NetFlow/ScoresAttacks.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "K-means with NetFlow entropy metrics": str(p) + "/Kmeans/NetFlow/ScoresAttacks.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "K-means with NetFlow combined feature set":  str(p) + "/Kmeans/NetFlow/ScoresAttacks.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json",

                        "K-means with telemetry measurements": str(p) + "/Kmeans/Telemetry/ScoresAttacks.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "K-means with telemetry entropy metrics": str(p) + "/Kmeans/Telemetry/ScoresAttacks.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "K-means with telemetry combined feature set": str(p) + "/Kmeans/Telemetry/ScoresAttacks.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json",

                        "Random Forest with NetFlow header fields": str(p) + "/RandomForest/NetFlow/ScoresAttacks.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "Random Forest with NetFlow header fields without IPs": str(p) + "/RandomForest/NetFlow/ScoresAttacks.FieldsNoIP.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "Random Forest with NetFlow entropy metrics": str(p) + "/RandomForest/NetFlow/ScoresAttacks.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "Random Forest with NetFlow combined feature set": str(p) + "/RandomForest/NetFlow/ScoresAttacks.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "Random Forest with NetFlow combined feature set  without IPs": str(p) + "/RandomForest/NetFlow/ScoresAttacks.CombinedNoIP."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json",

                        "Random Forest with telemetry measurements": str(p) + "/RandomForest/Telemetry/ScoresAttacks.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "Random Forest with telemetry entropy metrics": str(p) + "/RandomForest/Telemetry/ScoresAttacks.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "Random Forest with telemetry combined feature set": str(p) + "/RandomForest/Telemetry/ScoresAttacks.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json",

                        "Bytes in NetFlow records": str(p) + "/Threshold/NetFlow/ScoresAttacks.Bytes."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "Packets in NetFlow records": str(p) + "/Threshold/NetFlow/ScoresAttacks.Packets."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "Bi-directional flows in NetFlow records": str(p) + "/Threshold/NetFlow/ScoresAttacks.NumberOfFlows."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json",

                        "Ingress bytes in telemetry measurements":str(p) + "/Threshold/Telemetry/ScoresAttacks.NumberOfBytes_ingress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "Ingress packets in telemetry measurements": str(p) + "/Threshold/Telemetry/ScoresAttacks.NumberOfPackets_ingress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "Egress bytes in telemetry measurements": str(p) + "/Threshold/Telemetry/ScoresAttacks.NumberOfBytes_egress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "Egress packets in telemetry measurements": str(p) + "/Threshold/Telemetry/ScoresAttacks.NumberOfPackets_egress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json",

                        "Deviation score for egress queue size": str(p) + "/Threshold/Telemetry/ScoresAttacks.egress_queue_info__0__cur_buffer_occupancy.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "Deviation score for egress bytes/s": str(p) + "/Threshold/Telemetry/ScoresAttacks.egress_stats__if_1sec_octets.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "Deviation score for egress packets/s": str(p) + "/Threshold/Telemetry/ScoresAttacks.egress_stats__if_1sec_pkts.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "Deviation score for ingress bytes/s": str(p) + "/Threshold/Telemetry/ScoresAttacks.ingress_stats__if_1sec_octets.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "Deviation score for ingress packets/s": str(p) + "/Threshold/Telemetry/ScoresAttacks.ingress_stats__if_1sec_pkts.attack."+str(attackDate)+ "."+str(systemId)+ ".json",

                        "Deviation score for egress queue size using maximum variance": str(p) + "/Threshold/Telemetry/ScoresAttacks.MaxVar.egress_queue_info__0__cur_buffer_occupancy.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "Deviation score for egress bytes/s using maximum variance": str(p) + "/Threshold/Telemetry/ScoresAttacks.MaxVar.egress_stats__if_1sec_octets.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "Deviation score for egress packets/s using maximum variance": str(p) + "/Threshold/Telemetry/ScoresAttacks.MaxVar.egress_stats__if_1sec_pkts.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "Deviation score for ingress bytes/s using maximum variance": str(p) + "/Threshold/Telemetry/ScoresAttacks.MaxVar.ingress_stats__if_1sec_octets.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "Deviation score for ingress packets/s using maximum variance": str(p) + "/Threshold/Telemetry/ScoresAttacks.MaxVar.ingress_stats__if_1sec_pkts.attack."+str(attackDate)+ "."+str(systemId)+ ".json",

                        "ICMP destination unreachable packets": str(p) + "/Threshold/NetFlow/ScoresAttacks.ICMPDstUnreachable."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "ICMP packets": str(p) + "/Threshold/NetFlow/ScoresAttacks.ICMPPackets."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "ICMP ratio": str(p) + "/Threshold/NetFlow/ScoresAttacks.ICMPRatio."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json",

                        "Xmas flows": str(p) + "/Threshold/NetFlow/ScoresAttacks.Xmas.attack."+str(attackDate)+ "."+str(systemId)+ ".json",
                        "SYN flows": str(p) + "/Threshold/NetFlow/ScoresAttacks.SYN.attack."+str(attackDate)+ "."+str(systemId)+ ".json",

                        "Top 20 flows": str(p) + "/TopKFlows/NetFlow/ScoresAttacks.TopKFlows.attack."+str(attackDate)+ "."+str(systemId)+ ".json",

                        "Alert fusion: time": str(p) + "/Correlation/ScoresAttackTypes.Aggregation.json",
                        "Alert fusion: packet sizes": str(p) + "/Correlation/ScoresAttackTypes.CorrelationDistribution.json",
                        "Alert fusion: attack types": str(p) + "/Correlation/ScoresAttackTypes.CorrelationAttackType.json",
                        "Alert fusion: ranking": str(p) + "/Correlation/ScoresAttackTypes.Ranking.json",
                    }
                    

                    for detectionMethod, fileName in paths.items():
                        if not Path(fileName).exists():
                            print("NO FILE NAMED:", fileName)
                            continue
                        jsonFile = open(fileName, 'r')
                        data = json.load(jsonFile)
                        tp = data[attack]["TP"]
                        fp = data[attack]["FP"]
                        tn = data[attack]["TN"]
                        fn = data[attack]["FN"]
                        
                        if detectionMethod == "Bi-directional flows in NetFlow records":
                            print(tp, fp, tn ,fn)

                        if fp != 0 or tn != 0 or tp != 0 or fn != 0:
                            accuracy = (tp + tn)/(tp+tn+fp+fn)
                        else:
                            accuracy = np.nan
                        if fp != 0 or tn != 0:
                            fpr = fp/(fp + tn)
                        else:
                            fpr = np.nan
                        if fn != 0  or tp != 0:
                            fnr = fn/(fn + tp)
                        else:
                            fnr = np.nan
                        if tp != 0 or fp != 0:
                            precision = tp/(tp+fp)
                        else:
                            precision = np.nan
                        if  fn != 0 or tp != 0:
                            recall = tp/(tp+ fn)
                        else:
                            recall = np.nan
                        if tp != 0 or fp!= 0 or fn != 0:
                            f1 =2*tp/(2*tp+fp+fn)
                        else:
                            f1 = np.nan
                        if detectionMethod == "Bi-directional flows in NetFlow records":
                            print(f1, precision, recall, fnr, fpr, accuracy)

                        detectionMethods[detectionMethod]["Precision"].append(precision)
                        detectionMethods[detectionMethod]["F1"].append(f1)
                        detectionMethods[detectionMethod]["TPR"].append(recall)
                        detectionMethods[detectionMethod]["FNR"].append(fnr)
                        detectionMethods[detectionMethod]["FPR"].append(fpr)
                        detectionMethods[detectionMethod]["Accuracy"].append(accuracy)
  
        precisionArray = []
        f1Array = []
        tprArray = []
        fnrArray = []
        fprArray = []
        accuracyArray = []
        scores = list(detectionMethods.items())
        for key, value in scores:
            precisionArray.append(np.nanmean(value["Precision"]))
            f1Array.append(np.nanmean(value["F1"]))
            tprArray.append(np.nanmean(value["TPR"]))
            fnrArray.append(np.nanmean(value["FNR"]))
            fprArray.append(np.nanmean(value["FPR"]))
            accuracyArray.append(np.nanmean(value["Accuracy"]))
        precision_attackTypes.append(precisionArray)
        f1_attackTypes.append(f1Array)
        tpr_attackTypes.append(tprArray)
        fnr_attackTypes.append(fnrArray)
        fpr_attackTypes.append(fprArray)
        accuracy_attackTypes.append(accuracyArray)

    colorsGood = ["#E9D4C7","#CB997E", "#3A2D32"]
    colorsBad = ["#3A2D32","#CB997E", "#E9D4C7"]
    cmapGood = LinearSegmentedColormap.from_list("custom_cmap", colorsGood)
    cmapBad = LinearSegmentedColormap.from_list("custom_cmap", colorsBad)

    average_precision = []
    average_f1 = []
    average_tpr = []
    average_fnr = []
    average_fpr = []
    average_accuracy = []
    for i in range(len(precision_attackTypes)):
        average_precision.append("%.3f"%np.nanmean(precision_attackTypes[i]))
        average_f1.append("%.3f"%np.nanmean(f1_attackTypes[i]))
        average_tpr.append("%.3f"%np.nanmean(tpr_attackTypes[i]))
        average_fnr.append("%.3f"%np.nanmean(fnr_attackTypes[i]))
        average_fpr.append("%.3f"%np.nanmean(fpr_attackTypes[i]))
        average_accuracy.append("%.3f"%np.nanmean(accuracy_attackTypes[i]))
    precision_attackTypes = np.transpose(precision_attackTypes)
    f1_attackTypes = np.transpose(f1_attackTypes)
    tpr_attackTypes = np.transpose(tpr_attackTypes)
    fnr_attackTypes = np.transpose(fnr_attackTypes)
    fpr_attackTypes = np.transpose(fpr_attackTypes)
    accuracy_attackTypes = np.transpose(accuracy_attackTypes)

    fig, ax = plt.subplots(figsize=(13, 15))
    sns.heatmap(f1_attackTypes, annot=True, fmt=".3f", cmap=cmapGood, ax=ax)

    ax.set_xticklabels(average_f1, rotation = 0, ha='center')
    ax.set_yticklabels(list(detectionMethods.keys()), rotation = 0,ha='right')


    ax3 = ax.twiny()
    ax3.set_xticks(ax.get_xticks())
    ax3.set_xlim(ax.get_xlim())
    ax3.set_xticklabels(attackTypes, rotation = 30, ha='left')
    ax3.xaxis.tick_top()
    ax3.xaxis.set_label_position('top')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    fig.tight_layout()
    
    fig.savefig("Plots/AttackTypes.F1.pdf", dpi=300)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(13, 15))
    sns.heatmap(precision_attackTypes, annot=True, fmt=".3f", cmap=cmapGood, ax=ax)

    ax.set_xticklabels(average_precision, rotation = 0, ha='center')
    ax.set_yticklabels(list(detectionMethods.keys()), rotation = 0,ha='right')


    ax3 = ax.twiny()
    ax3.set_xticks(ax.get_xticks())
    ax3.set_xlim(ax.get_xlim())
    ax3.set_xticklabels(attackTypes, rotation = 30, ha='left')
    ax3.xaxis.tick_top()
    ax3.xaxis.set_label_position('top')
    fig.tight_layout()
    
    fig.savefig("Plots/AttackTypes.Precision.pdf", dpi=300)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(13, 15))
    sns.heatmap(tpr_attackTypes, annot=True, fmt=".3f", cmap=cmapGood, ax=ax)

    ax.set_xticklabels(average_tpr, rotation = 0, ha='center')
    ax.set_yticklabels(list(detectionMethods.keys()), rotation = 0,ha='right')


    ax3 = ax.twiny()
    ax3.set_xticks(ax.get_xticks())
    ax3.set_xlim(ax.get_xlim())
    ax3.set_xticklabels(attackTypes, rotation = 30, ha='left')
    ax3.xaxis.tick_top()
    ax3.xaxis.set_label_position('top')
    fig.tight_layout()
    
    fig.savefig("Plots/AttackTypes.TPR.pdf", dpi=300)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(13, 15))
    sns.heatmap(fpr_attackTypes, annot=True, fmt=".3f", cmap=cmapBad, ax=ax)

    ax.set_xticklabels(average_fpr, rotation = 0, ha='center')
    ax.set_yticklabels(list(detectionMethods.keys()), rotation = 0,ha='right')


    ax3 = ax.twiny()
    ax3.set_xticks(ax.get_xticks())
    ax3.set_xlim(ax.get_xlim())
    ax3.set_xticklabels(attackTypes, rotation = 30, ha='left')
    ax3.xaxis.tick_top()
    ax3.xaxis.set_label_position('top')
    fig.tight_layout()
    
    fig.savefig("Plots/AttackTypes.FPR.pdf", dpi=300)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(13, 15))
    sns.heatmap(fnr_attackTypes, annot=True, fmt=".3f", cmap=cmapBad, ax=ax)

    ax.set_xticklabels(average_fnr, rotation = 0, ha='center')
    ax.set_yticklabels(list(detectionMethods.keys()), rotation = 0,ha='right')


    ax3 = ax.twiny()
    ax3.set_xticks(ax.get_xticks())
    ax3.set_xlim(ax.get_xlim())
    ax3.set_xticklabels(attackTypes, rotation = 30, ha='left')
    ax3.xaxis.tick_top()
    ax3.xaxis.set_label_position('top')
    fig.tight_layout()
    
    fig.savefig("Plots/AttackTypes.FNR.pdf", dpi=300)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(13, 15))
    sns.heatmap(accuracy_attackTypes, annot=True, fmt=".3f", cmap=cmapGood, ax=ax)

    ax.set_xticklabels(average_accuracy, rotation = 0, ha='center')
    ax.set_yticklabels(list(detectionMethods.keys()), rotation = 0,ha='right')


    ax3 = ax.twiny()
    ax3.set_xticks(ax.get_xticks())
    ax3.set_xlim(ax.get_xlim())
    ax3.set_xticklabels(attackTypes, rotation = 30, ha='left')
    ax3.xaxis.tick_top()
    ax3.xaxis.set_label_position('top')
    fig.tight_layout()
    
    fig.savefig("Plots/AttackTypes.Accuracy.pdf", dpi=300)
    plt.close(fig)


intervals = [timedelta(minutes = 5),timedelta(minutes = 10), timedelta(minutes = 15)]
makeHeatMapAttackTypes(["TPR", "F1"], intervals, "24.03.23")