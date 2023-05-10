import math
import matplotlib.pyplot as plt
import json
from datetime import datetime, timedelta
import matplotlib.dates as mdates
import pandas as pd

'''
    Make a plot based on arrays of values and timestamps
'''
def plotKmeansFields(start, stop, clusterFrequency, systemId, attackDate):
    #Makes datetime objects of the input times
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    fig, axs = plt.subplots(2, 1, figsize=(20, 10))

    format = '%b %d %H:%M:%S'
    strings = [
            ["Mar 08 14:29:55", "Mar 08 14:34:56"], ["Mar 08 14:49:56", "Mar 08 15:02:57"],
            ["Mar 08 15:09:56", "Mar 08 15:17:02"], ["Mar 08 15:37:00", "Mar 08 15:52:02"]]
    for string in strings:
        start = datetime.strptime(string[0], format).replace(year=2023)
        stop = datetime.strptime(string[1], format).replace(year=2023)
        axs[0].axvspan(start, stop, facecolor="#F9CAA4")
        axs[1].axvspan(start, stop, facecolor="#F9CAA4")
    
    intervalTime = (stopTime - startTime).total_seconds()/clusterFrequency.total_seconds()
    timeAxis = []
    packetsClusterAttack = []
    packetsClusterNormal = []
    sTimeClusterAttack = []
    sTimeClusterNormal = []
    maxValue = 0
    #Loop for every minute in a week
    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + clusterFrequency
        clusterLabels = pd.read_csv("Calculations0803/Kmeans/NetFlow/ClusterLabelling.attack."+str(attackDate)+ ".stopTime" + stopTime.strftime("%H.%M.%S")+ "."+ str(systemId)+ ".csv")
        
        if clusterLabels["AttackCluster"][0] == 0:
            attackCluster = pd.read_csv("Calculations0803/Kmeans/NetFlow/Cluster0.attack."+str(attackDate)+ ".stopTime." + stopTime.strftime("%H.%M.%S")+ "."+ str(systemId)+ ".csv")
            nonAttackCluster = pd.read_csv("Calculations0803/Kmeans/NetFlow/Cluster1.attack."+str(attackDate)+ ".stopTime" + stopTime.strftime("%H.%M.%S")+ "."+ str(systemId)+ ".csv")
        
        elif clusterLabels["AttackCluster"][0] == 1:
            attackCluster = pd.read_csv("Calculations0803/Kmeans/NetFlow/Cluster1.attack."+str(attackDate)+ ".stopTime" + stopTime.strftime("%H.%M.%S")+ "."+ str(systemId)+ ".csv")
            nonAttackCluster = pd.read_csv("Calculations0803/Kmeans/NetFlow/Cluster0.attack."+str(attackDate)+ ".stopTime." + stopTime.strftime("%H.%M.%S")+ "."+ str(systemId)+ ".csv")
        
        sTimeAttack = pd.to_datetime(attackCluster["sTime"])
        sTimeNormal = pd.to_datetime(nonAttackCluster["sTime"])

        packetsAttack = attackCluster["packets"]
        labelsAttack = attackCluster["real_label"]
        packetsNormal = nonAttackCluster["packets"]
        labelsNormal = nonAttackCluster["real_label"]
        
        eTimeAttack = pd.to_datetime(attackCluster["eTime"])
        eTimeNormal = pd.to_datetime(nonAttackCluster["eTime"])

        lastInterval = pd.Interval(pd.Timestamp.now().replace(tzinfo=None), pd.Timestamp.now().replace(tzinfo=None), closed="both")

        for i in range(len(labelsAttack)):
            if labelsAttack[i] == 1:
                if sTimeAttack[i].replace(second=0).replace(tzinfo=None) in lastInterval and eTimeAttack[i].replace(second=0).replace(tzinfo=None) in lastInterval:
                    continue
                elif sTimeAttack[i].replace(second=0).replace(tzinfo=None) in lastInterval:

                    nowInterval = pd.Interval(lastInterval.right, eTimeAttack[i].replace(second=0).replace(tzinfo=None)+timedelta(minutes=1), closed="both")
                    lastInterval = pd.Interval(lastInterval.left, eTimeAttack[i].replace(second=0).replace(tzinfo=None) +timedelta(minutes=1), closed="both")
                
                elif eTimeAttack[i].replace(second=0).replace(tzinfo=None) in lastInterval:
            
                    nowInterval = pd.Interval(sTimeAttack[i].replace(second=0).replace(tzinfo=None), lastInterval.left, closed="both")
                    lastInterval = pd.Interval(sTimeAttack[i].replace(second=0).replace(tzinfo=None), lastInterval.right, closed="both")
                else:
                    nowInterval = pd.Interval(sTimeAttack[i].replace(second=0).replace(tzinfo=None), eTimeAttack[i].replace(second=0).replace(tzinfo=None) +timedelta(minutes=1), closed="both")
                    lastInterval = nowInterval

                axs[0].axvspan(nowInterval.left, nowInterval.right, facecolor="#2A9D8F")
            sTimeClusterAttack.append(sTimeAttack[i].replace(tzinfo=None))
            packetsClusterAttack.append(packetsAttack[i])
            if packetsAttack[i] > maxValue:
                maxValue = packetsAttack[i]
        for i in range(len(labelsNormal)):
            if labelsNormal[i] == 1:
                if sTimeNormal[i].replace(second=0).replace(tzinfo=None) in lastInterval and eTimeNormal[i].replace(second=0).replace(tzinfo=None) in lastInterval:
                    continue
                elif sTimeNormal[i].replace(second=0).replace(tzinfo=None) in lastInterval:

                    nowInterval = pd.Interval(lastInterval.right, eTimeNormal[i].replace(second=0).replace(tzinfo=None)+timedelta(minutes=1), closed="both")
                    lastInterval = pd.Interval(lastInterval.left, eTimeNormal[i].replace(second=0).replace(tzinfo=None) +timedelta(minutes=1), closed="both")
                
                elif sTimeNormal[i].replace(second=0).replace(tzinfo=None) in lastInterval:
            
                    nowInterval = pd.Interval(sTimeNormal[i].replace(second=0).replace(tzinfo=None), lastInterval.left, closed="both")
                    lastInterval = pd.Interval(sTimeNormal[i].replace(second=0).replace(tzinfo=None), lastInterval.right, closed="both")
                else:
                    nowInterval = pd.Interval(sTimeNormal[i].replace(second=0).replace(tzinfo=None), eTimeNormal[i].replace(second=0).replace(tzinfo=None) +timedelta(minutes=1), closed="both")
                    lastInterval = nowInterval

                axs[1].axvspan(nowInterval.left, nowInterval.right, facecolor="#2A9D8F")
            sTimeClusterNormal.append(sTimeNormal[i].replace(tzinfo=None))
            packetsClusterNormal.append(packetsNormal[i])

            if packetsNormal[i] > maxValue:
                maxValue = packetsNormal[i]

        startTime += clusterFrequency

    axs[0].plot(sTimeClusterAttack ,packetsClusterAttack, color="#162931", label="Attack cluster")

    axs[1].plot(sTimeClusterNormal ,packetsClusterNormal, color="#E76F51", label="Normal cluster")

    axs[0].xaxis.set(
        major_locator=mdates.MinuteLocator(interval=15),
        major_formatter=mdates.DateFormatter("%H:%M")
    )
    axs[0].set_title("Packets in each cluster")
    axs[0].title.set_size(20)
    axs[0].set_xlabel('Time')
    axs[0].set_ylabel("Packets")
    axs[0].set_ylim([0,maxValue])
    axs[0].tick_params(axis='both', which='major', labelsize=17)
    axs[0].legend()
    #axs[0].text(0.7, 0.9, 'Labeled attack cluster: ' + str(deviation), horizontalalignment='center', verticalalignment='center', transform=ax.transAxes, bbox=dict(facecolor='blue', alpha=0.2))

    axs[1].xaxis.set(
        major_locator=mdates.MinuteLocator(interval=15),
        major_formatter=mdates.DateFormatter("%H:%M")
    )
    axs[1].set_xlabel('Time')
    axs[1].set_ylabel("Packets")
    axs[1].set_ylim([0,maxValue])
    axs[1].tick_params(axis='both', which='major', labelsize=17)
    axs[1].legend()
    fig.tight_layout()
    fig.savefig("Plots/Kmeans/Attack0803/NetFlow/Fields/Packets.ClusterLabelling."+  str(systemId)+ ".png", dpi=300)
    plt.close()


systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
systems = ["bergen-gw3"]
startKmeans = "2023-03-08 14:15:00"
stopKmeans= "2023-03-08 16:00:00"
clusterFrequency = timedelta(minutes = 15)
attackDate = "08.03.23"
for systemId in systems:
    plotKmeansFields(startKmeans, stopKmeans, clusterFrequency, systemId, attackDate)
