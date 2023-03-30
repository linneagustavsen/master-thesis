import pandas as pd
import matplotlib.pyplot as plt
import matplotlib as mpl
mpl.rcParams['agg.path.chunksize'] = 10000


def makePlotFromCSV(csvFile,x_field, y_field, y_fieldName,path):
    data = pd.read_csv(csvFile)

    data[x_field] = pd.to_datetime(data[x_field])
    x = data[x_field]
    y = data[y_field]

    fig, ax = plt.subplots(1, 1, figsize=(20, 5))
    ax.plot(x,y)
    ax.set_title(y_fieldName)
    ax.set_xlabel('Time')
    ax.set_ylabel(y_fieldName)

    ax.tick_params(axis='both', which='major', labelsize=12)

    fig.tight_layout()
    fig.savefig(path+y_field+".png", dpi=300)

'''



metrics = ["srcEntropy","srcEntropyRate","dstEntropy","dstEntropyRate","flowEntropy","flowEntropyRate","numberOfFlows","icmpRatio","icmpPackets"]
metricName =["Entropy of source IP","Entropy rate of source IP","Entropy of destination IP","Entropy rate of destination IP","Entropy of bi-directional flow","Entropy rate of bi-directional flow","Number of flows","ICMP ratio","Number of ICMP packets"]
metrics300 = 'NetFlowCalculations/Entropy/Calculations/Metrics.300secInterval.attack.01.01.oslo-gw.csv'
metrics600 = 'NetFlowCalculations/Entropy/Calculations/Metrics.600secInterval.attack.01.01.oslo-gw.csv'
metrics900 = 'NetFlowCalculations/Entropy/Calculations/Metrics.600secInterval.attack.01.01.oslo-gw.csv'
for i in range(len(metrics)):
    path = 'Plots/Entropy/Metrics300'
    makePlotFromCSV(metrics300,'Time', metrics[i], metricName[i], path)
    path = 'Plots/Entropy/Metrics600'
    makePlotFromCSV(metrics600,'Time', metrics[i], metricName[i], path)
    path = 'Plots/Entropy/Metrics900'
    makePlotFromCSV(metrics900,'Time', metrics[i], metricName[i], path)

syn300 = 'NetFlowCalculations/Entropy/Calculations/SYN.300secInterval.attack.01.01.oslo-gw.csv'
syn600 = 'NetFlowCalculations/Entropy/Calculations/SYN.600secInterval.attack.01.01.oslo-gw.csv'
syn900 = 'NetFlowCalculations/Entropy/Calculations/SYN.900secInterval.attack.01.01.oslo-gw.csv'

syn = ["srcEntropy","dstEntropy","flowEntropy"]
synNames = ["Entropy of source IP","Entropy of destination IP", "Entropy of bi-directional flow"]
for i in range(len(syn)):
    path = 'Plots/Entropy/SYN300'
    makePlotFromCSV(syn300,'Time', syn[i], synNames[i], path)
    path = 'Plots/Entropy/SYN600'
    makePlotFromCSV(syn600,'Time', syn[i], synNames[i], path)
    path = 'Plots/Entropy/SYN900'
    makePlotFromCSV(syn900,'Time', syn[i], synNames[i], path)
#Kmeans
cluster0 = 'NetFlowCalculations/Kmeans/Calculations/Cluster0.attack.01.01.oslo-gw.csv'
cluster1 = 'NetFlowCalculations/Kmeans/Calculations/Cluster1.attack.01.01.oslo-gw.csv'
fields = ["packets","bytes","duration"]
for i in range(len(fields)):
    path = 'Plots/Kmeans/NormalCluster0'
    makePlotFromCSV(cluster0,'sTime', fields[i], fields[i], path)
    path = 'Plots/Kmeans/NormalCluster1'
    makePlotFromCSV(cluster1,'sTime', fields[i], fields[i], path)


combinedCluster0300 = 'NetFlowCalculations/Kmeans/Calculations/Combined.Cluster0.300secInterval.attack.01.01.oslo-gw.csv'
combinedCluster0600 = 'NetFlowCalculations/Kmeans/Calculations/Combined.Cluster0.600secInterval.attack.01.01.oslo-gw.csv'
combinedCluster0900 = 'NetFlowCalculations/Kmeans/Calculations/Combined.Cluster0.900secInterval.attack.01.01.oslo-gw.csv'

combinedCluster1300 = 'NetFlowCalculations/Kmeans/Calculations/Combined.Cluster1.300secInterval.attack.01.01.oslo-gw.csv'
combinedCluster1600 = 'NetFlowCalculations/Kmeans/Calculations/Combined.Cluster1.600secInterval.attack.01.01.oslo-gw.csv'
combinedCluster1900 = 'NetFlowCalculations/Kmeans/Calculations/Combined.Cluster1.900secInterval.attack.01.01.oslo-gw.csv'

fields = ["packets","bytes","duration", "entropy_ip_source","entropy_rate_ip_source","entropy_ip_destination","entropy_rate_ip_destination","entropy_flow","entropy_rate_flow","number_of_flows","icmp_ratio","number_of_icmp_packets"]
fieldNames = ["Number of packets", "Number of bytes", "Duration of flow", "Entropy of source IP","Entropy rate of source IP","Entropy of destination IP","Entropy rate of destination IP","Entropy of bi-directional flow","Entropy rate of bi-directional flow","Number of flows","ICMP ratio","Number of ICMP packets"]
for i in range(len(fields)):
    path = 'Plots/Kmeans/CombinedCluster0.300'
    makePlotFromCSV(combinedCluster0300,'Time', fields[i], fieldNames[i], path)
    path = 'Plots/Kmeans/CombinedCluster0.600'
    makePlotFromCSV(combinedCluster0600,'Time', fields[i], fieldNames[i], path)
    path = 'Plots/Kmeans/CombinedCluster0.900'
    makePlotFromCSV(combinedCluster0900,'Time', fields[i], fieldNames[i], path)

    path = 'Plots/Kmeans/CombinedCluster1.300'
    makePlotFromCSV(combinedCluster1300,'Time', fields[i], fieldNames[i], path)
    path = 'Plots/Kmeans/CombinedCluster1.600'
    makePlotFromCSV(combinedCluster1600,'Time', fields[i], fieldNames[i], path)
    path = 'Plots/Kmeans/CombinedCluster1.900'
    makePlotFromCSV(combinedCluster1900,'Time', fields[i], fieldNames[i], path)


 


entropyCluster0300 = 'NetFlowCalculations/Kmeans/Calculations/Entropy.Cluster0.300secInterval.attack.01.01.oslo-gw.csv'
entropyCluster0600 = 'NetFlowCalculations/Kmeans/Calculations/Entropy.Cluster0.600secInterval.attack.01.01.oslo-gw.csv'
entropyCluster0900 = 'NetFlowCalculations/Kmeans/Calculations/Entropy.Cluster0.900secInterval.attack.01.01.oslo-gw.csv'

entropyCluster1300 = 'NetFlowCalculations/Kmeans/Calculations/Entropy.Cluster1.300secInterval.attack.01.01.oslo-gw.csv'
entropyCluster1600 = 'NetFlowCalculations/Kmeans/Calculations/Entropy.Cluster1.600secInterval.attack.01.01.oslo-gw.csv'
entropyCluster1900 = 'NetFlowCalculations/Kmeans/Calculations/Entropy.Cluster1.900secInterval.attack.01.01.oslo-gw.csv'


fields = ["entropy_ip_source","entropy_rate_ip_source","entropy_ip_destination","entropy_rate_ip_destination","entropy_flow","entropy_rate_flow","number_of_flows","icmp_ratio","number_of_icmp_packets"]
fieldNames = ["Entropy of source IP","Entropy rate of source IP","Entropy of destination IP","Entropy rate of destination IP","Entropy of bi-directional flow","Entropy rate of bi-directional flow","Number of flows","ICMP ratio","Number of ICMP packets"]

for i in range(len(fields)):
    path = 'Plots/Kmeans/EntropyCluster0.300'
    makePlotFromCSV(entropyCluster0300,'Time', fields[i], fieldNames[i], path)
    path = 'Plots/Kmeans/EntropyCluster0.600'
    makePlotFromCSV(entropyCluster0300,'Time', fields[i], fieldNames[i], path)
    path = 'Plots/Kmeans/EntropyCluster0.900'
    makePlotFromCSV(entropyCluster0300,'Time', fields[i], fieldNames[i], path)

    path = 'Plots/Kmeans/EntropyCluster1.300'
    makePlotFromCSV(entropyCluster0300,'Time', fields[i], fieldNames[i], path)
    path = 'Plots/Kmeans/EntropyCluster1.600'
    makePlotFromCSV(entropyCluster0300,'Time', fields[i], fieldNames[i], path)
    path = 'Plots/Kmeans/EntropyCluster1.900'
    makePlotFromCSV(entropyCluster0300,'Time', fields[i], fieldNames[i], path)
#RandomForest
#Threshold
icmpDst = 'NetFlowCalculations/Threshold/Calculations/ICMPDstUnreachable.attack.01.01.oslo-gw.csv'
synThreshold = 'NetFlowCalculations/Threshold/Calculations/SYN.attack.01.01.oslo-gw.csv'

path = 'Plots/Threshold/ICMPDstUnreachable'
#makePlotFromCSV(icmpDst,'Time', "ICMPDstUnreachable", "ICMP destination unreachable packets per flow", path)
path = 'Plots/Threshold/SYN'
makePlotFromCSV(synThreshold,'Time', "synPacketsPerFlow", "SYN packets per flow", path)

'''