import math
import matplotlib.pyplot as plt
import json
from datetime import datetime, timedelta
import matplotlib.dates as mdates
import pandas as pd

'''
    Make a plot based on arrays of values and timestamps
'''
def plotKmeansFields(start, stop, interval, clusterFrequency, systemId, attackDate):
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
    packetsCluster0 = []
    packetsCluster1 = []
    sTimeCluster0 = []
    sTimeCluster1 = []
    #Loop for every minute in a week
    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + clusterFrequency
  

        cluster0 = pd.read_csv("Calculations0803/Kmeans/NetFlow/Combined.Cluster0."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime." + stopTime.strftime("%H.%M.%S")+ "."+ str(systemId)+ ".csv")
        cluster1 = pd.read_csv("Calculations0803/Kmeans/NetFlow/Combined.Cluster1."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime." + stopTime.strftime("%H.%M.%S")+ "."+ str(systemId)+ ".csv")
        sTime0 = pd.to_datetime(cluster0["sTime"])
        sTime1 = pd.to_datetime(cluster1["sTime"])

        packets0 = cluster0["packets"]
        labels0 = cluster0["real_label"]
        packets1 = cluster1["packets"]
        labels1 = cluster1["real_label"]
        
        
        #format = '%Y-%m-%dT%H:%M:%SZ'
        eTime0 = pd.to_datetime(cluster0["eTime"])
        eTime1 = pd.to_datetime(cluster1["eTime"])

        lastInterval = pd.Interval(pd.Timestamp.now().replace(tzinfo=None), pd.Timestamp.now().replace(tzinfo=None), closed="both")

        for i in range(len(labels0)):
            if labels0[i] == 1:
                if sTime0[i].replace(second=0).replace(tzinfo=None) in lastInterval and eTime0[i].replace(second=0).replace(tzinfo=None) in lastInterval:
                    continue
                elif sTime0[i].replace(second=0).replace(tzinfo=None) in lastInterval:

                    nowInterval = pd.Interval(lastInterval.right, eTime0[i].replace(second=0).replace(tzinfo=None)+timedelta(minutes=1), closed="both")
                    lastInterval = pd.Interval(lastInterval.left, eTime0[i].replace(second=0).replace(tzinfo=None) +timedelta(minutes=1), closed="both")
                
                elif eTime0[i].replace(second=0).replace(tzinfo=None) in lastInterval:
            
                    nowInterval = pd.Interval(sTime0[i].replace(second=0).replace(tzinfo=None), lastInterval.left, closed="both")
                    lastInterval = pd.Interval(sTime0[i].replace(second=0).replace(tzinfo=None), lastInterval.right, closed="both")
                else:
                    nowInterval = pd.Interval(sTime0[i].replace(second=0).replace(tzinfo=None), eTime0[i].replace(second=0).replace(tzinfo=None) +timedelta(minutes=1), closed="both")
                    lastInterval = nowInterval

                axs[0].axvspan(nowInterval.left, nowInterval.right, facecolor="#2A9D8F")
            sTimeCluster0.append(sTime0[i].replace(tzinfo=None))
            packetsCluster0.append(packets0[i])
        for i in range(len(labels1)):
            if labels1[i] == 1:
                if sTime1[i].replace(second=0).replace(tzinfo=None) in lastInterval and eTime1[i].replace(second=0).replace(tzinfo=None) in lastInterval:
                    continue
                elif sTime1[i].replace(second=0).replace(tzinfo=None) in lastInterval:

                    nowInterval = pd.Interval(lastInterval.right, eTime1[i].replace(second=0).replace(tzinfo=None)+timedelta(minutes=1), closed="both")
                    lastInterval = pd.Interval(lastInterval.left, eTime1[i].replace(second=0).replace(tzinfo=None) +timedelta(minutes=1), closed="both")
                
                elif eTime1[i].replace(second=0).replace(tzinfo=None) in lastInterval:
            
                    nowInterval = pd.Interval(sTime1[i].replace(second=0).replace(tzinfo=None), lastInterval.left, closed="both")
                    lastInterval = pd.Interval(sTime1[i].replace(second=0).replace(tzinfo=None), lastInterval.right, closed="both")
                else:
                    nowInterval = pd.Interval(sTime1[i].replace(second=0).replace(tzinfo=None), eTime1[i].replace(second=0).replace(tzinfo=None) +timedelta(minutes=1), closed="both")
                    lastInterval = nowInterval

                axs[1].axvspan(nowInterval.left, nowInterval.right, facecolor="#2A9D8F")
            sTimeCluster1.append(sTime1[i].replace(tzinfo=None))
            packetsCluster1.append(packets1[i])
        startTime += clusterFrequency

    axs[0].scatter(sTimeCluster0 ,packetsCluster0, color="#162931", label="Cluster 0")

    axs[1].scatter(sTimeCluster1 ,packetsCluster1, color="#E76F51", label="Cluster 1")

    axs[0].xaxis.set(
        major_locator=mdates.MinuteLocator(interval=15),
        major_formatter=mdates.DateFormatter("%H:%M")
    )
    axs[0].set_title("Packets in cluster 0")
    axs[0].set_xlabel('Time')
    axs[0].set_ylabel("Packets")
    axs[0].tick_params(axis='both', which='major', labelsize=12)
    axs[0].legend()
    #axs[0].text(0.7, 0.9, 'Labeled attack cluster: ' + str(deviation), horizontalalignment='center', verticalalignment='center', transform=ax.transAxes, bbox=dict(facecolor='blue', alpha=0.2))
    
    axs[1].set_title("Packets in each cluster 1")
    axs[1].xaxis.set(
        major_locator=mdates.MinuteLocator(interval=15),
        major_formatter=mdates.DateFormatter("%H:%M")
    )
    axs[1].set_xlabel('Time')
    axs[1].set_ylabel("Packets")
    axs[1].tick_params(axis='both', which='major', labelsize=12)
    axs[1].legend()
    fig.tight_layout()
    fig.savefig("Plots/Kmeans/Attack0803/NetFlow/Combined/Packets.Scatter."+  str(systemId)+ "."+ str(int(interval.total_seconds())) +"secInterval.png", dpi=300)
    plt.close()


systems = [ "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
startKmeans = "2023-03-08 14:15:00"
stopKmeans= "2023-03-08 16:00:00"
clusterFrequency = timedelta(minutes = 15)
intervals = [timedelta(minutes = 5), timedelta(minutes = 10), timedelta(minutes = 15)]
attackDate = "08.03.23"
for systemId in systems:
    for interval in intervals:
        if interval == timedelta(minutes=15):
            plotKmeansFields(startKmeans, stopKmeans, interval, timedelta(minutes=30), systemId, attackDate)
        else:
            plotKmeansFields(startKmeans, stopKmeans, interval, clusterFrequency, systemId, attackDate)
    break