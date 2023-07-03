from datetime import timedelta
from pathlib import Path
from matplotlib.colors import LinearSegmentedColormap, ListedColormap, LogNorm
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import pandas as pd

def makeStackedBar(metric, interval, attackDate):
    if attackDate == "08.03.23":
        fileString = "0803"
    elif attackDate == "17.03.23":
        fileString = "1703"
    elif attackDate == "24.03.23":
        fileString = "2403"
        
    if interval == timedelta(minutes = 5):
        windowSize = "5min"
    elif interval == timedelta(minutes = 10):
        windowSize = "10min"
    elif interval == timedelta(minutes = 15):
        windowSize = "15min"
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
    detectionMethods = {
        "Entropy of destination IP addresses": [],
        "Entropy of source IP addresses": [],
        "Entropy of bi-directional flows": [],
        "Entropy rate of destination IP addresses": [],
        "Entropy rate of source IP addresses": [],
        "Entropy rate of bi-directional flows": [],

        "Entropy of packet sizes": [],
        "Entropy rate of packet sizes": [],

        "Entropy of ingress packet sizes": [],
        "Entropy rate of ingress packet sizes": [],
        "Entropy of egress packet sizes": [],
        "Entropy rate of egress packet sizes": [],
        
        "Entropy of destination IP addresses with SYN flag": [],
        "Entropy of source IP addresses with SYN flag": [],
        "Entropy of bi-directional flows with SYN flag": [],

        "K-means with NetFlow header fields": [],
        "K-means with NetFlow entropy metrics": [],
        "K-means with NetFlow combined feature set": [],

        "K-means with telemetry measurements": [],
        "K-means with telemetry entropy metrics": [],
        "K-means with telemetry combined feature set": [],

        "Random Forest with NetFlow header fields": [],
        "Random Forest with NetFlow header fields without IPs": [],
        "Random Forest with NetFlow entropy metrics": [],
        "Random Forest with NetFlow combined feature set": [],
        "Random Forest with NetFlow combined feature set  without IPs": [],

        "Random Forest with telemetry measurements": [],
        "Random Forest with telemetry entropy metrics": [],
        "Random Forest with telemetry combined feature set": [],

        "Bytes in NetFlow records": [],
        "Packets in NetFlow records": [],
        "Bi-directional flows in NetFlow records": [],

        "Ingress bytes in telemetry measurements": [],
        "Ingress packets in telemetry measurements": [],
        "Egress bytes in telemetry measurements": [],
        "Egress packets in telemetry measurements": [],

        "Deviation score for egress queue size": [],
        "Deviation score for egress bytes/s": [],
        "Deviation score for egress packets/s": [],
        "Deviation score for ingress bytes/s": [],
        "Deviation score for ingress packets/s": [],

        "Deviation score for egress queue size using maximum variance": [],
        "Deviation score for egress bytes/s using maximum variance": [],
        "Deviation score for egress packets/s using maximum variance": [],
        "Deviation score for ingress bytes/s using maximum variance": [],
        "Deviation score for ingress packets/s using maximum variance": [],

        "ICMP destination unreachable packets": [],
        "ICMP packets": [],
        "ICMP ratio": [],

        "Xmas flows": [],
        "SYN flows": [],

        "Top 20 flows": [],
        
    }
    
    systems = ["trd-gw", "ifi2-gw5", "bergen-gw3", "tromso-gw5",  "teknobyen-gw1", "hoytek-gw2"]
    p = Path('Detections' + fileString +"_"+ windowSize +"_"+ metric)
    for systemId in systems:
        paths = {
            "Entropy of destination IP addresses": str(p) + "/Entropy/NetFlow/Scores.DestinationIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv",
            "Entropy of source IP addresses": str(p) + "/Entropy/NetFlow/Scores.SourceIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv",
            "Entropy of bi-directional flows": str(p) + "/Entropy/NetFlow/Scores.FlowEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv",
            "Entropy rate of destination IP addresses": str(p) + "/Entropy/NetFlow/Scores.DestinationIPEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv",
            "Entropy rate of source IP addresses": str(p) + "/Entropy/NetFlow/Scores.SourceIPEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv",
            "Entropy rate of bi-directional flows":  str(p) + "/Entropy/NetFlow/Scores.FlowEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv",

            "Entropy of packet sizes":  str(p) + "/Entropy/NetFlow/Scores.PacketSizeEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv",
            "Entropy rate of packet sizes": str(p) + "/Entropy/NetFlow/Scores.PacketSizeEntropyRate."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv",

            "Entropy of ingress packet sizes": str(p) + "/Entropy/Telemetry/Scores.EntropyPacketSize_ingress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv",
            "Entropy rate of ingress packet sizes": str(p) + "/Entropy/Telemetry/Scores.EntropyRatePacketSize_ingress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv",
            "Entropy of egress packet sizes": str(p) + "/Entropy/Telemetry/Scores.EntropyPacketSize_egress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv",
            "Entropy rate of egress packet sizes": str(p) + "/Entropy/Telemetry/Scores.EntropyRatePacketSize_egress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv",
            
            "Entropy of destination IP addresses with SYN flag": str(p) + "/Entropy/NetFlow/Scores.SYNDestinationIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv",
            "Entropy of source IP addresses with SYN flag": str(p) + "/Entropy/NetFlow/Scores.SYNSourceIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv",
            "Entropy of bi-directional flows with SYN flag": str(p) + "/Entropy/NetFlow/Scores.SYNFlowIPEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv",

            "K-means with NetFlow header fields": str(p) + "/Kmeans/NetFlow/Scores.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "K-means with NetFlow entropy metrics": str(p) + "/Kmeans/NetFlow/Scores.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "K-means with NetFlow combined feature set":  str(p) + "/Kmeans/NetFlow/Scores.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",

            "K-means with telemetry measurements": str(p) + "/Kmeans/Telemetry/Scores.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "K-means with telemetry entropy metrics": str(p) + "/Kmeans/Telemetry/Scores.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "K-means with telemetry combined feature set": str(p) + "/Kmeans/Telemetry/Scores.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",

            "Random Forest with NetFlow header fields": str(p) + "/RandomForest/NetFlow/Scores.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "Random Forest with NetFlow header fields without IPs": str(p) + "/RandomForest/NetFlow/Scores.FieldsNoIP.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "Random Forest with NetFlow entropy metrics": str(p) + "/RandomForest/NetFlow/Scores.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "Random Forest with NetFlow combined feature set": str(p) + "/RandomForest/NetFlow/Scores.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "Random Forest with NetFlow combined feature set  without IPs": str(p) + "/RandomForest/NetFlow/Scores.CombinedNoIP."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",

            "Random Forest with telemetry measurements": str(p) + "/RandomForest/Telemetry/Scores.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "Random Forest with telemetry entropy metrics": str(p) + "/RandomForest/Telemetry/Scores.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "Random Forest with telemetry combined feature set": str(p) + "/RandomForest/Telemetry/Scores.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",

            "Bytes in NetFlow records": str(p) + "/Threshold/NetFlow/Scores.Bytes."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "Packets in NetFlow records": str(p) + "/Threshold/NetFlow/Scores.Packets."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "Bi-directional flows in NetFlow records": str(p) + "/Threshold/NetFlow/Scores.NumberOfFlows."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",

            "Ingress bytes in telemetry measurements":str(p) + "/Threshold/Telemetry/Scores.NumberOfBytes_ingress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "Ingress packets in telemetry measurements": str(p) + "/Threshold/Telemetry/Scores.NumberOfPackets_ingress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "Egress bytes in telemetry measurements": str(p) + "/Threshold/Telemetry/Scores.NumberOfBytes_egress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "Egress packets in telemetry measurements": str(p) + "/Threshold/Telemetry/Scores.NumberOfPackets_egress."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",

            "Deviation score for egress queue size": str(p) + "/Threshold/Telemetry/Scores.egress_queue_info__0__cur_buffer_occupancy.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "Deviation score for egress bytes/s": str(p) + "/Threshold/Telemetry/Scores.egress_stats__if_1sec_octets.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "Deviation score for egress packets/s": str(p) + "/Threshold/Telemetry/Scores.egress_stats__if_1sec_pkts.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "Deviation score for ingress bytes/s": str(p) + "/Threshold/Telemetry/Scores.ingress_stats__if_1sec_octets.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "Deviation score for ingress packets/s": str(p) + "/Threshold/Telemetry/Scores.ingress_stats__if_1sec_pkts.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",

            "Deviation score for egress queue size using maximum variance": str(p) + "/Threshold/Telemetry/Scores.MaxVar.egress_queue_info__0__cur_buffer_occupancy.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "Deviation score for egress bytes/s using maximum variance": str(p) + "/Threshold/Telemetry/Scores.MaxVar.egress_stats__if_1sec_octets.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "Deviation score for egress packets/s using maximum variance": str(p) + "/Threshold/Telemetry/Scores.MaxVar.egress_stats__if_1sec_pkts.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "Deviation score for ingress bytes/s using maximum variance": str(p) + "/Threshold/Telemetry/Scores.MaxVar.ingress_stats__if_1sec_octets.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "Deviation score for ingress packets/s using maximum variance": str(p) + "/Threshold/Telemetry/Scores.MaxVar.ingress_stats__if_1sec_pkts.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",

            "ICMP destination unreachable packets": str(p) + "/Threshold/NetFlow/Scores.ICMPDstUnreachable."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "ICMP packets": str(p) + "/Threshold/NetFlow/Scores.ICMPPackets."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "ICMP ratio": str(p) + "/Threshold/NetFlow/Scores.ICMPRatio."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",

            "Xmas flows": str(p) + "/Threshold/NetFlow/Scores.Xmas.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
            "SYN flows": str(p) + "/Threshold/NetFlow/Scores.SYN.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",

            "Top 20 flows": str(p) + "/TopKFlows/NetFlow/Scores.TopKFlows.attack."+str(attackDate)+ "."+str(systemId)+ ".csv",
        }

        for detectionMethod, fileName in paths.items():
            if not Path(fileName).exists():
                print("NO FILE NAMED:", fileName)
                continue
            data = pd.read_csv(fileName)
            totalAlerts = 0
            totalAlerts += data["TP"][0]
            totalAlerts += data["FP"][0]
            allAlerts += totalAlerts
            detectionMethods[detectionMethod].append(totalAlerts)
            if "K-means" in detectionMethod:
                kmeansAlerts += totalAlerts
            print(systemId, detectionMethod)
            print(allAlerts)

    '''totalAlerts = {}
    for detectionMethod, array in detectionMethods.items():
        totalAlerts[detectionMethod] = sum(array)
    alerts = sorted(totalAlerts.items(), key=lambda x:x[1], reverse=True)
    for detectionMethod, numberOfAlerts in alerts:
        print(detectionMethod, "\t\t\t",numberOfAlerts )'''
    colorsGood = ["#E9D4C7","#CB997E", "#3A2D32"]
    colorsBad = ["#3A2D32","#CB997E", "#E9D4C7"]
    cmapGood = LinearSegmentedColormap.from_list("custom_cmap", colorsGood)
    cmapBad = LinearSegmentedColormap.from_list("custom_cmap", colorsBad)
    alerts = [value for key, value in detectionMethods.items()]
    print(len(paths))
    fig, ax = plt.subplots(figsize=(13, 15))
    sns.heatmap(alerts, annot=True, fmt=",.0f", cmap=cmapGood, ax=ax, norm=LogNorm())

    ax.set_xticklabels(routers, rotation = 30, ha='right')
    ax.set_yticklabels(list(detectionMethods.keys()), rotation = 0,ha='right')

    # Manually create a colorbar
    #cbar = ax.collections[0].colorbar
    #cbar.set_ticks([0, 0.5, 0.99])
    #cbar.set_ticklabels(['Low', 'Medium', 'High'])
    ax.set_title("Total amount of alerts: " + f'{allAlerts:,}')
    fig.tight_layout()
    fig.savefig("Plots/Alerts." + str(int(interval.total_seconds()))+"."+ metric+".pdf", dpi=300)
    plt.close(fig)
    ''' width = 0.5

    fig, ax = plt.subplots()
    earthy_palette = ['#7a5230', '#b07850', '#856447', '#b99974', '#645c4f', '#c5a880', '#8b5e3a', '#bc936d', '#a38363', '#d2bfaa',
                  '#735941', '#a97f60', '#8b6f4b', '#bd9868', '#7c6750', '#e0c7b0', '#8a6648', '#d3aa83', '#947b62', '#e5c5a5',
                  '#967d60', '#c5a17e', '#a07751', '#8f7962', '#c6ae98', '#806f61', '#b8996b', '#7e6b52', '#b89775', '#685647',
                  '#8e7b6b', '#9e8365', '#cc9f78', '#78694e', '#b3a37a', '#9c7c61', '#a58968', '#8d7353', '#af8d6b', '#8f7c69',
                  '#d8b998', '#8c7c5d', '#e0c29f', '#7c694f', '#d8b68e', '#73664b', '#c4a578', '#5e503d', '#a89170', '#725d49']
    colors = ['#543005','#8c510a','#bf812d','#dfc27d','#f6e8c3','#c7eae5','#80cdc1','#35978f','#01665e','#003c30']
    bottom = np.zeros(6)

    counter= 0
    #colors = sns.color_palette("blend:#997B66,#e0c7b0,#797D62,#c6ae98,#8c7c5d", n_colors=len(detectionMethods))
    colors = sns.color_palette("pastel", n_colors=len(detectionMethods))
    for name, alerts in detectionMethods.items():
        p = ax.bar(routers, alerts, width, label=name, bottom=bottom, color = colors[counter])
        bottom += alerts
        counter +=1

    ax.set_title("Number of alerts for each detection method on each router")
    fig.legend(loc="upper right")

    plt.show()'''

makeStackedBar("TPR", timedelta(minutes=5), "24.03.23")
makeStackedBar("TPR", timedelta(minutes=10), "24.03.23")
makeStackedBar("TPR", timedelta(minutes=15), "24.03.23")

makeStackedBar("F1", timedelta(minutes=5), "24.03.23")
makeStackedBar("F1", timedelta(minutes=10), "24.03.23")
makeStackedBar("F1", timedelta(minutes=15), "24.03.23")