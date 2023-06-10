import math
import matplotlib.pyplot as plt
import json
from datetime import datetime, timedelta
import matplotlib.dates as mdates
import pandas as pd

'''
    Make a plot based on arrays of values and timestamps
'''
def plotKmeansEntropy(start, stop, interval, systemId, attackDate):
    if attackDate == "08.03.23":
        fileString = "0803"
        strings = [
            ["Mar 08 14:29:55", "Mar 08 14:34:56"], ["Mar 08 14:49:56", "Mar 08 15:02:57"],
            ["Mar 08 15:09:56", "Mar 08 15:17:02"], ["Mar 08 15:37:00", "Mar 08 15:52:02"]]
        attacks = ["SYN Flood", "SlowLoris", "Ping Flood", "R.U.D.Y"]
        colors = ["#CB997E","#DDBEA9", "#99958C", "#B7B7A4", "#7F6A93"]
        startTime = datetime.strptime("2023-03-08 14:15:00", '%Y-%m-%d %H:%M:%S')
        stopTime = datetime.strptime("2023-03-08 16:00:00", '%Y-%m-%d %H:%M:%S')
    elif attackDate == "17.03.23":
        fileString = "1703"
        strings = [["Mar 17 11:00:01", "Mar 17 11:07:02"], ["Mar 17 11:37:02", "Mar 17 11:50:04"],
           ["Mar 17 11:57:02", "Mar 17 12:04:12"], ["Mar 17 12:44:10", "Mar 17 13:00:17"]]
        attacks = ["SYN Flood", "SlowLoris", "Ping Flood", "R.U.D.Y"]
        colors = ["#CB997E","#DDBEA9", "#99958C", "#B7B7A4", "#7F6A93"]
        startTime = datetime.strptime("2023-03-17 11:00:00", '%Y-%m-%d %H:%M:%S')
        stopTime = datetime.strptime("2023-03-17 13:00:00", '%Y-%m-%d %H:%M:%S')
    elif attackDate == "24.03.23":
        fileString = "2403"
        strings = [["Mar 24 14:00:01", "Mar 24 14:03:57"], ["Mar 24 14:13:29", "Mar 24 14:29:08"],
           ["Mar 24 14:46:30", "Mar 24 14:55:00"], ["Mar 24 14:59:50", "Mar 24 15:15:06"], 
           ["Mar 24 15:26:51", "Mar 24 15:39:22"], ["Mar 24 15:40:21", "Mar 24 15:47:50"], 
           ["Mar 24 16:07:29", "Mar 24 16:19:00"], ["Mar 24 16:22:29", "Mar 24 16:29:13"],
           ["Mar 24 16:29:53", "Mar 24 16:49:50"], ["Mar 24 16:53:22", "Mar 24 17:09:39"],
           ["Mar 24 17:25:15", "Mar 24 17:47:00"]]
        attacks = ["UDP Flood", "SlowLoris", "Ping Flood", "Slow Read", "Blacknurse", "SYN Flood", "R.U.D.Y",
                "Xmas", "UDP Flood\nand SlowLoris", "Ping Flood\nand R.U.D.Y", "All types"]
        colors = ['#CABBB1','#BDAA9D','#AD9585','#997B66','#D08C60',"#DAA684",'#FFC876','#F1DCA7','#D9AE94','#9B9B7A','#797D62', "#7F6A93"]
        startTime = datetime.strptime("2023-03-24 14:00:00", '%Y-%m-%d %H:%M:%S')
        stopTime = datetime.strptime("2023-03-24 18:00:00", '%Y-%m-%d %H:%M:%S')
    #Makes datetime objects of the input times
    fig, axs = plt.subplots(1, 1, figsize=(20, 10))

    format = '%b %d %H:%M:%S'
    counterStrings = 0
    for string in strings:
        start = datetime.strptime(string[0], format).replace(year=2023)
        stop = datetime.strptime(string[1], format).replace(year=2023)
        axs.axvspan(start, stop, facecolor=colors[counterStrings], label=attacks[counterStrings])
        counterStrings += 1

    clusterLabels = pd.read_csv("Calculations"+ fileString+ "/Kmeans/NetFlow/Entropy.ClusterLabelling."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")

    cluster = pd.read_csv("Calculations"+ fileString+ "/Kmeans/NetFlow/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
    
    sTime0 = pd.to_datetime(cluster["sTime"])
    
    packets0 = cluster["number_of_packets"]
    labels0 = cluster["real_label"]
    
    if 1 not in labels0.values :
        print("No attacks")
        return
    #format = '%Y-%m-%dT%H:%M:%SZ'
    eTime0 = pd.to_datetime(cluster["eTime"])
    

    lastInterval = pd.Interval(pd.Timestamp.now().replace(tzinfo=None), pd.Timestamp.now().replace(tzinfo=None), closed="both")
    for i in range(len(labels0)):
        sTime0[i] = sTime0[i].replace(tzinfo=None)
        eTime0[i] = eTime0[i].replace(tzinfo=None)
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

            axs.axvspan(nowInterval.left, nowInterval.right, facecolor=colors[-1])

    labelPlot1 = ""
    labelPlot2 = ""

    if len(clusterLabels["AttackCluster"]) == 0:
        return

    axs.scatter(sTime0 ,packets0, color="darkRed", label="Attack cluster")

    axs.xaxis.set(
        major_locator=mdates.MinuteLocator(interval=15),
        major_formatter=mdates.DateFormatter("%H:%M")
    )
    axs.set_title("Packets in each cluster")
    axs.title.set_size(20)
    axs.set_xlabel('Time', fontsize=20)
    axs.set_ylabel("Packets", fontsize=20)
    #axs.ylabel.set_size(15)
    #axs.xlabel.set_size(15)
    axs.tick_params(axis='both', which='major', labelsize=15)
    fig.legend(fontsize=20)
    
    
    fig.tight_layout()
    fig.savefig("Plots/Kmeans/Attack"+ fileString+ "/NetFlow/Entropy/Packets.ClusterLabelling."+  str(systemId)+ "."+ str(int(interval.total_seconds())) +"secInterval.png", dpi=500)
    plt.close(fig)


systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
startKmeans = "2023-03-08 14:15:00"
stopKmeans= "2023-03-08 16:00:00"
intervals = [timedelta(minutes = 5), timedelta(minutes = 10), timedelta(minutes = 15)]
attackDates = ["17.03.23","24.03.23"]
for attackDate in attackDates:
    for systemId in systems:
        for interval in intervals:
            plotKmeansEntropy(startKmeans, stopKmeans, interval, systemId, attackDate)